// SPDX-License-Identifier: GPL-2.0
/*
 * NVMe I/O command implementation.
 * Copyright (c) 2015-2016 HGST, a Western Digital Company.
 */
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
#include <linux/blkdev.h>
#include <linux/module.h>
#include "nvmet.h"

#include <linux/filter.h>
#include <linux/bpf.h>
#include <linux/kthread.h>

#include <linux/smp.h>
#include <linux/ktime.h>

extern struct nvmet_ebpf ebpf;

extern struct bpf_prog *pblk_bpf_prog;


struct pblk_ctx{
	int param0;
	int param1;
	int param2;
	int param3;
	int param4;
	void *data;
	void *map_page;
	int nlb;
};

void nvmet_bdev_set_limits(struct block_device *bdev, struct nvme_id_ns *id)
{
	const struct queue_limits *ql = &bdev_get_queue(bdev)->limits;
	/* Number of logical blocks per physical block. */
	const u32 lpp = ql->physical_block_size / ql->logical_block_size;
	/* Logical blocks per physical block, 0's based. */
	const __le16 lpp0b = to0based(lpp);

	/*
	 * For NVMe 1.2 and later, bit 1 indicates that the fields NAWUN,
	 * NAWUPF, and NACWU are defined for this namespace and should be
	 * used by the host for this namespace instead of the AWUN, AWUPF,
	 * and ACWU fields in the Identify Controller data structure. If
	 * any of these fields are zero that means that the corresponding
	 * field from the identify controller data structure should be used.
	 */
	id->nsfeat |= 1 << 1;
	id->nawun = lpp0b;
	id->nawupf = lpp0b;
	id->nacwu = lpp0b;

	/*
	 * Bit 4 indicates that the fields NPWG, NPWA, NPDG, NPDA, and
	 * NOWS are defined for this namespace and should be used by
	 * the host for I/O optimization.
	 */
	id->nsfeat |= 1 << 4;
	/* NPWG = Namespace Preferred Write Granularity. 0's based */
	id->npwg = lpp0b;
	/* NPWA = Namespace Preferred Write Alignment. 0's based */
	id->npwa = id->npwg;
	/* NPDG = Namespace Preferred Deallocate Granularity. 0's based */
	id->npdg = to0based(ql->discard_granularity / ql->logical_block_size);
	/* NPDG = Namespace Preferred Deallocate Alignment */
	id->npda = id->npdg;
	/* NOWS = Namespace Optimal Write Size */
	id->nows = to0based(ql->io_opt / ql->logical_block_size);
}

int nvmet_bdev_ns_enable(struct nvmet_ns *ns)
{
	int ret;

	ns->bdev = blkdev_get_by_path(ns->device_path,
			FMODE_READ | FMODE_WRITE, NULL);
	if (IS_ERR(ns->bdev)) {
		ret = PTR_ERR(ns->bdev);
		if (ret != -ENOTBLK) {
			pr_err("failed to open block device %s: (%ld)\n",
					ns->device_path, PTR_ERR(ns->bdev));
		}
		ns->bdev = NULL;
		return ret;
	}
	ns->size = i_size_read(ns->bdev->bd_inode);
	ns->blksize_shift = blksize_bits(bdev_logical_block_size(ns->bdev));
	return 0;
}

void nvmet_bdev_ns_disable(struct nvmet_ns *ns)
{
	if (ns->bdev) {
		blkdev_put(ns->bdev, FMODE_WRITE | FMODE_READ);
		ns->bdev = NULL;
	}
}

static u16 blk_to_nvme_status(struct nvmet_req *req, blk_status_t blk_sts)
{
	u16 status = NVME_SC_SUCCESS;

	if (likely(blk_sts == BLK_STS_OK))
		return status;
	/*
	 * Right now there exists M : 1 mapping between block layer error
	 * to the NVMe status code (see nvme_error_status()). For consistency,
	 * when we reverse map we use most appropriate NVMe Status code from
	 * the group of the NVMe staus codes used in the nvme_error_status().
	 */
	switch (blk_sts) {
		case BLK_STS_NOSPC:
			status = NVME_SC_CAP_EXCEEDED | NVME_SC_DNR;
			req->error_loc = offsetof(struct nvme_rw_command, length);
			break;
		case BLK_STS_TARGET:
			status = NVME_SC_LBA_RANGE | NVME_SC_DNR;
			req->error_loc = offsetof(struct nvme_rw_command, slba);
			break;
		case BLK_STS_NOTSUPP:
			req->error_loc = offsetof(struct nvme_common_command, opcode);
			switch (req->cmd->common.opcode) {
				case nvme_cmd_dsm:
				case nvme_cmd_write_zeroes:
					status = NVME_SC_ONCS_NOT_SUPPORTED | NVME_SC_DNR;
					break;
				default:
					status = NVME_SC_INVALID_OPCODE | NVME_SC_DNR;
			}
			break;
		case BLK_STS_MEDIUM:
			status = NVME_SC_ACCESS_DENIED;
			req->error_loc = offsetof(struct nvme_rw_command, nsid);
			break;
		case BLK_STS_IOERR:
			/* fallthru */
		default:
			status = NVME_SC_INTERNAL | NVME_SC_DNR;
			req->error_loc = offsetof(struct nvme_common_command, opcode);
	}

	switch (req->cmd->common.opcode) {
		case nvme_cmd_read:
		case nvme_cmd_write:
			req->error_slba = le64_to_cpu(req->cmd->rw.slba);
			break;
		case nvme_cmd_write_zeroes:
			req->error_slba =
				le64_to_cpu(req->cmd->write_zeroes.slba);
			break;
		default:
			req->error_slba = 0;
	}
	return status;
}

static void nvmet_bio_isp_done(struct bio *bio){
	/*struct nvmet_req *req = bio->bi_private;

	  struct pblk_ctx ctx;

	  int npages=0;
	  int size=0;
	  int ret=-1;
	  int order = 0;

	  u64 start, end;
	  u64 us, ns;
	  int cpuid = smp_processor_id();

	  pblk_end_time = ktime_get_ns();
	  pblk_read_time = pblk_end_time - req->bio_issue_time;
	  printk("pblk(ISP) - CPU %d: read request %llu.%lluus\n",cpuid, pblk_read_time/1000, pblk_read_time - (pblk_read_time / 1000) * 1000);

	  npages = bio->bi_max_vecs;
	  size = 4096;
	  for(order = 0 ;order < 10 ; order++){
	  if(npages * 4096 <= size){
	  break;
	  }
	  size *= 2;
	  }
	  if(req->cmd == 0 || req->cmd == NULL){
	//printk("ISP - CPU %d: err - req ->cmd is NULL!\n",cpuid);
	nvmet_set_result(req, ret);
	nvmet_req_complete(req, blk_to_nvme_status(req, bio->bi_status));
	return;
	}

	ctx.param0=req->cmd->common.cdw2[0];
	ctx.param1=req->cmd->common.cdw2[1];
	ctx.param2=0;
	ctx.param3=0;
	ctx.param4=0;
	ctx.data =page_address(bio->bi_io_vec[0].bv_page);
	ctx.map_page = 0;
	ctx.nlb= req->cmd->rw.length+1;
	start = ktime_get_ns();
	if(pblk_bpf_prog){
	ret = BPF_PROG_RUN(pblk_bpf_prog, &ctx);
	}
	end = ktime_get_ns();
	us = (end-start)/1000;
	ns = (end-start) - us*1000;
	printk("ISP - CPU %d: eBPF program returned %d: %llu.%lluus\n",cpuid, ret, us, ns);
	nvmet_set_result(req, ret);
	free_pages((unsigned long)ctx.data,order);

	nvmet_req_complete(req, blk_to_nvme_status(req, bio->bi_status));
	if (bio != &req->b.inline_bio)
	bio_put(bio);*/
}

static void nvmet_bio_done(struct bio *bio)
{
	struct nvmet_req *req = bio->bi_private;

	/*u64 slba = 0;
	int cpuid = smp_processor_id();

	slba = le64_to_cpu(req->cmd->rw.slba);
	if(slba >= 1024){
		pblk_end_time = ktime_get_ns();
		pblk_read_time = pblk_end_time - req->bio_issue_time;
		printk("pblk - CPU %d: read request %llu.%lluus\n",cpuid, pblk_read_time/1000, pblk_read_time - (pblk_read_time / 1000) * 1000);
	}*/

	nvmet_req_complete(req, blk_to_nvme_status(req, bio->bi_status));
	if (bio != &req->b.inline_bio)
		bio_put(bio);
}

static void nvmet_bdev_execute_rw(struct nvmet_req *req)
{
	int sg_cnt = req->sg_cnt;
	struct bio *bio;
	struct scatterlist *sg;
	sector_t sector;
	int op, op_flags = 0, i;
	u64 slba = 0;

	int cpuid = smp_processor_id();
	struct pblk_ctx ctx;
	int ret=-1;
	int order = 0;
	struct page *pages = NULL;
	u64 start, end;
	u64 us, ns;

	if (!req->sg_cnt && req->cmd->rw.opcode != nvme_cmd_isp_read && req->cmd->rw.opcode != nvme_cmd_isp_page_clear) {
		nvmet_req_complete(req, 0);
		return;
	}

	if (req->cmd->rw.opcode == nvme_cmd_write) {
		op = REQ_OP_WRITE;
		op_flags = REQ_SYNC | REQ_IDLE;
		if (req->cmd->rw.control & cpu_to_le16(NVME_RW_FUA))
			op_flags |= REQ_FUA;
	}
	/*else if (req->cmd->rw.opcode == nvme_cmd_isp_read) {
	  op = REQ_OP_ISP_READ;
	  }*/
	else if (req->cmd->rw.opcode == nvme_cmd_isp_insert){
		op = REQ_OP_ISP_INSERT;
	}
	else if (req->cmd->rw.opcode == nvme_cmd_isp_page_read){
		op = REQ_OP_ISP_PAGE_READ;
	}
	else {
		op = REQ_OP_READ;
	}

	if (is_pci_p2pdma_page(sg_page(req->sg)))
		op_flags |= REQ_NOMERGE;

	sector = le64_to_cpu(req->cmd->rw.slba);
	sector <<= (req->ns->blksize_shift - 9);

	if (req->cmd->rw.opcode == nvme_cmd_isp_read) {	
		bio = bio_alloc(GFP_KERNEL, min(req->cmd->rw.length + 1, BIO_MAX_PAGES));
	}
	else{
		if (req->data_len <= NVMET_MAX_INLINE_DATA_LEN) {
			bio = &req->b.inline_bio;
			bio_init(bio, req->inline_bvec, ARRAY_SIZE(req->inline_bvec));
		} else {
			bio = bio_alloc(GFP_KERNEL, min(sg_cnt, BIO_MAX_PAGES));
		}
	}
	bio_set_dev(bio, req->ns->bdev);
	bio->bi_iter.bi_sector = sector;
	bio->bi_private = req;
	if (req->cmd->rw.opcode == nvme_cmd_isp_read){
		bio->bi_end_io = nvmet_bio_isp_done;
	}
	else{
		bio->bi_end_io = nvmet_bio_done;
	}
	bio_set_op_attrs(bio, op, op_flags);

	if (req->cmd->rw.opcode == nvme_cmd_isp_read) {	
		int npages = bio->bi_max_vecs;
		int size = 4096;
		int add_size = 0;
		u64 pblk_start_time = 0;
		u64 pblk_end_time = 0;
		u64 pblk_read_time = 0;
		for(order = 0 ;order < 10 ; order++){
			if(npages * 4096 <= size){
				break;
			}
			size *= 2;
		}
		pages = alloc_pages(GFP_KERNEL, order);
		add_size = bio_add_page(bio, pages, size, 0);
		if(add_size != size){
			printk(KERN_EMERG "nvmet: not enough bio size: requested %d / added %d\n", size, add_size);
		}	
		pblk_start_time = ktime_get_ns();		
		submit_bio_wait(bio);
	  	pblk_end_time = ktime_get_ns();
	  	pblk_read_time = pblk_end_time - pblk_start_time;
	  	printk("pblk(ISP) - CPU %d: read request %llu.%lluus\n",cpuid, pblk_read_time/1000, pblk_read_time - (pblk_read_time / 1000) * 1000);
		/*
		 * I/O operation finished. Process eBPF program.
		 */
		ctx.param0=req->cmd->common.cdw2[0];
		ctx.param1=req->cmd->common.cdw2[1];
		ctx.param2=req->cmd->common.cdw12;
		ctx.param3=0;
		ctx.param4=0;
		ctx.data =page_address(pages);
		ctx.map_page = page_address(ebpf.map_page[0]);
		ctx.nlb= req->cmd->rw.length+1;
		start = ktime_get_ns();
		if(pblk_bpf_prog){
			ret = BPF_PROG_RUN(pblk_bpf_prog, &ctx);
		}
		end = ktime_get_ns();
		us = (end-start)/1000;
		ns = (end-start) - us*1000;
		printk("ISP - CPU %d: eBPF program returned %d: %llu.%lluus\n",cpuid, ret, us, ns);
		nvmet_set_result(req, ret);
		free_pages((unsigned long)ctx.data,order);

		nvmet_req_complete(req, blk_to_nvme_status(req, bio->bi_status));
		if (bio != &req->b.inline_bio)
			bio_put(bio);
	}
	else if (req->cmd->rw.opcode == nvme_cmd_isp_page_clear){
		void *page = page_address(ebpf.map_page[0]);
		memset(page,0,4096);
		printk(KERN_INFO "nvmet: map_page clear issued\n");
		bio_endio(bio);
	}
	else{
		for_each_sg(req->sg, sg, req->sg_cnt, i) {
			while (bio_add_page(bio, sg_page(sg), sg->length, sg->offset)
					!= sg->length) {
				struct bio *prev = bio;

				bio = bio_alloc(GFP_KERNEL, min(sg_cnt, BIO_MAX_PAGES));
				bio_set_dev(bio, req->ns->bdev);
				bio->bi_iter.bi_sector = sector;
				bio_set_op_attrs(bio, op, op_flags);

				bio_chain(bio, prev);
				submit_bio(prev);
			}

			sector += sg->length >> 9;
			sg_cnt--;
		}
		/*slba = le64_to_cpu(req->cmd->rw.slba);
		if(slba >= 1024){
			req->bio_issue_time = ktime_get_ns();
		}*/
		if (req->cmd->rw.opcode == nvme_cmd_isp_page_read) {
			void *data = bio_data(bio);
			void *page = page_address(ebpf.map_page[0]);
			memcpy(data, page, 4096);
			bio_endio(bio);
		}
		else{
			submit_bio(bio);
		}
	}

}

static void nvmet_bdev_execute_flush(struct nvmet_req *req)
{
	struct bio *bio = &req->b.inline_bio;

	bio_init(bio, req->inline_bvec, ARRAY_SIZE(req->inline_bvec));
	bio_set_dev(bio, req->ns->bdev);
	bio->bi_private = req;
	bio->bi_end_io = nvmet_bio_done;
	bio->bi_opf = REQ_OP_WRITE | REQ_PREFLUSH;

	submit_bio(bio);
}

u16 nvmet_bdev_flush(struct nvmet_req *req)
{
	if (blkdev_issue_flush(req->ns->bdev, GFP_KERNEL, NULL))
		return NVME_SC_INTERNAL | NVME_SC_DNR;
	return 0;
}

static u16 nvmet_bdev_discard_range(struct nvmet_req *req,
		struct nvme_dsm_range *range, struct bio **bio)
{
	struct nvmet_ns *ns = req->ns;
	int ret;

	ret = __blkdev_issue_discard(ns->bdev,
			le64_to_cpu(range->slba) << (ns->blksize_shift - 9),
			le32_to_cpu(range->nlb) << (ns->blksize_shift - 9),
			GFP_KERNEL, 0, bio);
	if (ret && ret != -EOPNOTSUPP) {
		req->error_slba = le64_to_cpu(range->slba);
		return errno_to_nvme_status(req, ret);
	}
	return NVME_SC_SUCCESS;
}

static void nvmet_bdev_execute_discard(struct nvmet_req *req)
{
	struct nvme_dsm_range range;
	struct bio *bio = NULL;
	int i;
	u16 status;

	for (i = 0; i <= le32_to_cpu(req->cmd->dsm.nr); i++) {
		status = nvmet_copy_from_sgl(req, i * sizeof(range), &range,
				sizeof(range));
		if (status)
			break;

		status = nvmet_bdev_discard_range(req, &range, &bio);
		if (status)
			break;
	}

	if (bio) {
		bio->bi_private = req;
		bio->bi_end_io = nvmet_bio_done;
		if (status) {
			bio->bi_status = BLK_STS_IOERR;
			bio_endio(bio);
		} else {
			submit_bio(bio);
		}
	} else {
		nvmet_req_complete(req, status);
	}
}

static void nvmet_bdev_execute_dsm(struct nvmet_req *req)
{
	switch (le32_to_cpu(req->cmd->dsm.attributes)) {
		case NVME_DSMGMT_AD:
			nvmet_bdev_execute_discard(req);
			return;
		case NVME_DSMGMT_IDR:
		case NVME_DSMGMT_IDW:
		default:
			/* Not supported yet */
			nvmet_req_complete(req, 0);
			return;
	}
}

static void nvmet_bdev_execute_write_zeroes(struct nvmet_req *req)
{
	struct nvme_write_zeroes_cmd *write_zeroes = &req->cmd->write_zeroes;
	struct bio *bio = NULL;
	sector_t sector;
	sector_t nr_sector;
	int ret;

	sector = le64_to_cpu(write_zeroes->slba) <<
		(req->ns->blksize_shift - 9);
	nr_sector = (((sector_t)le16_to_cpu(write_zeroes->length) + 1) <<
			(req->ns->blksize_shift - 9));

	ret = __blkdev_issue_zeroout(req->ns->bdev, sector, nr_sector,
			GFP_KERNEL, &bio, 0);
	if (bio) {
		bio->bi_private = req;
		bio->bi_end_io = nvmet_bio_done;
		submit_bio(bio);
	} else {
		nvmet_req_complete(req, errno_to_nvme_status(req, ret));
	}
}

u16 nvmet_bdev_parse_io_cmd(struct nvmet_req *req)
{
	struct nvme_command *cmd = req->cmd;

	switch (cmd->common.opcode) {
		case nvme_cmd_read:
		case nvme_cmd_write:
		case nvme_cmd_isp_insert:
		case nvme_cmd_isp_page_read:
			req->execute = nvmet_bdev_execute_rw;
			req->data_len = nvmet_rw_len(req);
			return 0;
		case nvme_cmd_isp_read:
		case nvme_cmd_isp_page_clear:
			req->execute = nvmet_bdev_execute_rw;
			req->data_len = 0;
			return 0;
		case nvme_cmd_flush:
			req->execute = nvmet_bdev_execute_flush;
			req->data_len = 0;
			return 0;
		case nvme_cmd_dsm:
			req->execute = nvmet_bdev_execute_dsm;
			req->data_len = (le32_to_cpu(cmd->dsm.nr) + 1) *
				sizeof(struct nvme_dsm_range);
			return 0;
		case nvme_cmd_write_zeroes:
			req->execute = nvmet_bdev_execute_write_zeroes;
			req->data_len = 0;
			return 0;
		default:
			pr_err("unhandled cmd %d on qid %d\n", cmd->common.opcode,
					req->sq->qid);
			req->error_loc = offsetof(struct nvme_common_command, opcode);
			return NVME_SC_INVALID_OPCODE | NVME_SC_DNR;
	}
}
