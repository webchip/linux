/*
 * sun8i-ce-core.c - hardware cryptographic accelerator for Allwinner H3/A64 SoC
 *
 * Copyright (C) 2015-2017 Corentin Labbe <clabbe.montjoie@gmail.com>
 *
 * Core file which registers crypto algorithms supported by the CryptoEngine.
 *
 * You could find a link for the datasheet in Documentation/arm/sunxi/README
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */
#include <linux/clk.h>
#include <linux/irq.h>
#include <linux/crypto.h>
#include <linux/io.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/platform_device.h>
#include <crypto/scatterwalk.h>
#include <linux/scatterlist.h>
#include <linux/interrupt.h>
#include <linux/delay.h>
#include <linux/reset.h>
#include <crypto/sha.h>
#include <crypto/internal/hash.h>
#include <linux/dma-mapping.h>

#include "sun8i-ss.h"

static const u32 ce_md5_init[MD5_DIGEST_SIZE / 4] = {
	MD5_H0, MD5_H1, MD5_H2, MD5_H3
};

static const u32 ce_sha1_init[SHA1_DIGEST_SIZE / 4] = {
	cpu_to_be32(SHA1_H0), cpu_to_be32(SHA1_H1),
	cpu_to_be32(SHA1_H2), cpu_to_be32(SHA1_H3),
	cpu_to_be32(SHA1_H4),
};

static const u32 ce_sha224_init[SHA256_DIGEST_SIZE / 4] = {
	cpu_to_be32(SHA224_H0), cpu_to_be32(SHA224_H1),
	cpu_to_be32(SHA224_H2), cpu_to_be32(SHA224_H3),
	cpu_to_be32(SHA224_H4), cpu_to_be32(SHA224_H5),
	cpu_to_be32(SHA224_H6), cpu_to_be32(SHA224_H7),
};

static const u32 ce_sha256_init[SHA256_DIGEST_SIZE / 4] = {
	cpu_to_be32(SHA256_H0), cpu_to_be32(SHA256_H1),
	cpu_to_be32(SHA256_H2), cpu_to_be32(SHA256_H3),
	cpu_to_be32(SHA256_H4), cpu_to_be32(SHA256_H5),
	cpu_to_be32(SHA256_H6), cpu_to_be32(SHA256_H7),
};

static const u64 ce_sha384_init[SHA512_DIGEST_SIZE / 8] = {
	cpu_to_be64(SHA384_H0), cpu_to_be64(SHA384_H1),
	cpu_to_be64(SHA384_H2), cpu_to_be64(SHA384_H3),
	cpu_to_be64(SHA384_H4), cpu_to_be64(SHA384_H5),
	cpu_to_be64(SHA384_H6), cpu_to_be64(SHA384_H7),
};

static const u64 ce_sha512_init[SHA512_DIGEST_SIZE / 8] = {
	cpu_to_be64(SHA512_H0), cpu_to_be64(SHA512_H1),
	cpu_to_be64(SHA512_H2), cpu_to_be64(SHA512_H3),
	cpu_to_be64(SHA512_H4), cpu_to_be64(SHA512_H5),
	cpu_to_be64(SHA512_H6), cpu_to_be64(SHA512_H7),
};

int get_engine_number(struct sun8i_ss_ctx *ss)
{
	int e = ss->flow;

	ss->flow++;
	if (ss->flow >= MAXCHAN)
		ss->flow = 0;

	return e;
}

/* compact an sglist to a more "compact" sglist
 * With a maximum of 8 SGs
 * */
int sun8i_ss_compact(struct scatterlist *sg, unsigned int len)
{
	int numsg;
	struct scatterlist *sglist;
	int i;
	void *buf;
	unsigned int offset = 0;
	int copied;

	/* determine the number of sgs necessary */
	numsg = len / PAGE_SIZE + 1;
	if (numsg > 8)
		return -EINVAL;
	sglist = kcalloc(numsg, sizeof(struct scatterlist), GFP_KERNEL);
	if (!sglist)
		return -ENOMEM;
	sg_init_table(sglist, numsg);
	for (i = 0; i < numsg; i++) {
		buf = kmalloc(PAGE_SIZE, GFP_KERNEL);
		if (!buf)
			return -ENOMEM;
		sg_set_buf(&sglist[i], buf, PAGE_SIZE);
		copied = sg_pcopy_to_buffer(sg, sg_nents(sg), buf, PAGE_SIZE, offset);
		pr_info("%d Copied %d at %u\n", i, copied, offset);
		offset += copied;
	}
	return 0;
}

/* copy all data from an sg to a plain buffer for channel flow */
int sun8i_ss_bounce_src(struct ablkcipher_request *areq, int flow)
{
	struct crypto_ablkcipher *tfm = crypto_ablkcipher_reqtfm(areq);
	struct sun8i_tfm_ctx *op = crypto_ablkcipher_ctx(tfm);
	struct sun8i_ss_ctx *ss = op->ss;

	if (areq->nbytes > 4096)
		return -EINVAL;

	ss->chanlist[flow].bufsrc = kmalloc(areq->nbytes, GFP_KERNEL);
	if (!ss->chanlist[flow].bufsrc)
		return -ENOMEM;

	sg_copy_to_buffer(areq->src, sg_nents(areq->src),
			  ss->chanlist[flow].bufsrc, areq->nbytes);

	ss->chanlist[flow].bounce_src = kcalloc(1, sizeof(struct scatterlist),
						GFP_KERNEL);
	if (!ss->chanlist[flow].bounce_src)
		return -ENOMEM;

	sg_init_table(ss->chanlist[flow].bounce_src, 1);
	sg_set_buf(ss->chanlist[flow].bounce_src, ss->chanlist[flow].bufsrc,
		   areq->nbytes);

	return 0;
}

/* create a destination bounce buffer */
int sun8i_ss_bounce_dst(struct ablkcipher_request *areq, int flow)
{
	struct crypto_ablkcipher *tfm = crypto_ablkcipher_reqtfm(areq);
	struct sun8i_tfm_ctx *op = crypto_ablkcipher_ctx(tfm);
	struct sun8i_ss_ctx *ss = op->ss;

	if (areq->nbytes > 4096)
		return -EINVAL;

	ss->chanlist[flow].bufdst = kmalloc(areq->nbytes, GFP_KERNEL);
	if (!ss->chanlist[flow].bufdst)
		return -ENOMEM;

	ss->chanlist[flow].bounce_dst = kcalloc(1, sizeof(struct scatterlist),
						GFP_KERNEL);
	if (!ss->chanlist[flow].bounce_dst)
		return -ENOMEM;

	sg_init_table(ss->chanlist[flow].bounce_dst, 1);
	sg_set_buf(ss->chanlist[flow].bounce_dst, ss->chanlist[flow].bufdst,
		   areq->nbytes);

	return 0;
}
/*
int sun8i_ss_prep_src(struct ablkcipher_request *areq, int flow, struct scatterlist *in_sg)
{
	struct crypto_ablkcipher *tfm = crypto_ablkcipher_reqtfm(areq);
	struct sun8i_tfm_ctx *op = crypto_ablkcipher_ctx(tfm);
	struct sun8i_ss_ctx *ss = op->ss;
	unsigned int todo;
	unsigned int len;
	struct ss_task *cet;

	cet = ss->tl[flow];
	len = areq->nbytes;
	for_each_sg(in_sg, sg, nr_sgs, i) {
		cet->t_src[i].addr = sg_dma_address(sg);
		todo = min(len, sg_dma_len(sg));
		cet->t_src[i].len = todo / 4;
		len -= todo;
	}
	return 0;
}
*/

int handle_hash_request(struct crypto_engine *engine, struct ahash_request *areq)
{
	int err;
	err = sun8i_hash(areq);
	crypto_finalize_hash_request(engine, areq, err);

	return 0;
}

irqreturn_t ss_irq_handler(int irq, void *data)
{
	u32 p;
	struct sun8i_ss_ctx *ss = (struct sun8i_ss_ctx *)data;
	int flow = 0;

	p = readl(ss->base + CE_ISR);
	/*dev_info(ss->dev, "%s %d, %x\n", __func__, irq, p);*/
	for (flow = 0; flow < MAXCHAN; flow++) {
		if (p & (1 << flow)) {
			writel(1 << flow, ss->base + CE_ISR);
			/*dev_info(ss->dev, "Acked %d\n", flow);*/
			ss->chanlist[flow].status = 1;
			complete(&ss->chanlist[flow].complete);
		}
	}

	return IRQ_HANDLED;
}

static struct sun8i_ss_alg_template ss_algs[] = {
{	.type = CRYPTO_ALG_TYPE_ABLKCIPHER,
	.alg.crypto = {
		.cra_name = "cbc(aes)",
		.cra_driver_name = "cbc-aes-sun8i-ss",
		.cra_priority = 300,
		.cra_blocksize = AES_BLOCK_SIZE,
		.cra_flags = CRYPTO_ALG_TYPE_ABLKCIPHER | CRYPTO_ALG_ASYNC |
			CRYPTO_ALG_NEED_FALLBACK,
		.cra_ctxsize = sizeof(struct sun8i_tfm_ctx),
		.cra_module = THIS_MODULE,
		.cra_alignmask = 3,
		.cra_type = &crypto_ablkcipher_type,
		.cra_init = sun8i_ss_cipher_init,
		.cra_exit = sun8i_ss_cipher_exit,
		.cra_ablkcipher = {
			.min_keysize	= AES_MIN_KEY_SIZE,
			.max_keysize	= AES_MAX_KEY_SIZE,
			.ivsize		 = AES_BLOCK_SIZE,
			.setkey		 = sun8i_ss_aes_setkey,
			.encrypt		= sun8i_ss_cbc_aes_encrypt,
			.decrypt		= sun8i_ss_cbc_aes_decrypt,
		}
	}
},
{	.type = CRYPTO_ALG_TYPE_AHASH,
	.mode = SS_OP_MD5,
	.hash_init = ce_md5_init,
	.alg.hash = {
		.init = sun8i_hash_init,
		.update = sun8i_hash_update,
		.final = sun8i_hash_final,
		.finup = sun8i_hash_finup,
		.digest = sun8i_hash_digest,
		.export = sun8i_hash_export_md5,
		.import = sun8i_hash_import_md5,
		.halg = {
			.digestsize = MD5_DIGEST_SIZE,
			.statesize = sizeof(struct md5_state),
			.base = {
				.cra_name = "md5",
				.cra_driver_name = "md5-sun8i-ss",
				.cra_priority = 300,
				.cra_alignmask = 3,
				.cra_flags = CRYPTO_ALG_TYPE_AHASH |
					CRYPTO_ALG_ASYNC |
					CRYPTO_ALG_NEED_FALLBACK,
				.cra_blocksize = MD5_HMAC_BLOCK_SIZE,
				.cra_ctxsize = sizeof(struct sun8i_hash_req_ctx),
				.cra_module = THIS_MODULE,
				.cra_type = &crypto_ahash_type,
				.cra_init = sun8i_hash_crainit,
			}
		}
	}
},
{	.type = CRYPTO_ALG_TYPE_AHASH,
	.mode = SS_OP_SHA1,
	.hash_init = ce_sha1_init,
	.alg.hash = {
		.init = sun8i_hash_init,
		.update = sun8i_hash_update,
		.final = sun8i_hash_final,
		.finup = sun8i_hash_finup,
		.digest = sun8i_hash_digest,
		.export = sun8i_hash_export_sha1,
		.import = sun8i_hash_import_sha1,
		.halg = {
			.digestsize = SHA1_DIGEST_SIZE,
			.statesize = sizeof(struct sha1_state),
			.base = {
				.cra_name = "sha1",
				.cra_driver_name = "sha1-sun8i-ss",
				.cra_priority = 300,
				.cra_alignmask = 3,
				.cra_flags = CRYPTO_ALG_TYPE_AHASH |
					CRYPTO_ALG_ASYNC |
					CRYPTO_ALG_NEED_FALLBACK,
				.cra_blocksize = SHA1_BLOCK_SIZE,
				.cra_ctxsize = sizeof(struct sun8i_hash_req_ctx),
				.cra_module = THIS_MODULE,
				.cra_type = &crypto_ahash_type,
				.cra_init = sun8i_hash_crainit
			}
		}
	}
},
{	.type = CRYPTO_ALG_TYPE_AHASH,
	.mode = SS_OP_SHA224,
	.hash_init = ce_sha224_init,
	.alg.hash = {
		.init = sun8i_hash_init,
		.update = sun8i_hash_update,
		.final = sun8i_hash_final,
		.finup = sun8i_hash_finup,
		.digest = sun8i_hash_digest,
		.export = sun8i_hash_export_sha256,
		.import = sun8i_hash_import_sha256,
		.halg = {
			.digestsize = SHA224_DIGEST_SIZE,
			.statesize = sizeof(struct sha256_state),
			.base = {
				.cra_name = "sha224",
				.cra_driver_name = "sha224-sun8i-ss",
				.cra_priority = 300,
				.cra_alignmask = 3,
				.cra_flags = CRYPTO_ALG_TYPE_AHASH |
					CRYPTO_ALG_ASYNC |
					CRYPTO_ALG_NEED_FALLBACK,
				.cra_blocksize = SHA224_BLOCK_SIZE,
				.cra_ctxsize = sizeof(struct sun8i_hash_req_ctx),
				.cra_module = THIS_MODULE,
				.cra_type = &crypto_ahash_type,
				.cra_init = sun8i_hash_crainit
			}
		}
	}
},
{	.type = CRYPTO_ALG_TYPE_AHASH,
	.mode = SS_OP_SHA256,
	.hash_init = ce_sha256_init,
	.alg.hash = {
		.init = sun8i_hash_init,
		.update = sun8i_hash_update,
		.final = sun8i_hash_final,
		.finup = sun8i_hash_finup,
		.digest = sun8i_hash_digest,
		.export = sun8i_hash_export_sha256,
		.import = sun8i_hash_import_sha256,
		.halg = {
			.digestsize = SHA256_DIGEST_SIZE,
			.statesize = sizeof(struct sha256_state),
			.base = {
				.cra_name = "sha256",
				.cra_driver_name = "sha256-sun8i-ss",
				.cra_priority = 300,
				.cra_alignmask = 3,
				.cra_flags = CRYPTO_ALG_TYPE_AHASH |
					CRYPTO_ALG_ASYNC |
					CRYPTO_ALG_NEED_FALLBACK,
				.cra_blocksize = SHA256_BLOCK_SIZE,
				.cra_ctxsize = sizeof(struct sun8i_hash_req_ctx),
				.cra_module = THIS_MODULE,
				.cra_type = &crypto_ahash_type,
				.cra_init = sun8i_hash_crainit
			}
		}
	}
},
{	.type = CRYPTO_ALG_TYPE_AHASH,
	.mode = SS_OP_SHA384,
	.hash_init = ce_sha384_init,
	.alg.hash = {
		.init = sun8i_hash_init,
		.update = sun8i_hash_update,
		.final = sun8i_hash_final,
		.finup = sun8i_hash_finup,
		.digest = sun8i_hash_digest,
		.export = sun8i_hash_export_sha512,
		.import = sun8i_hash_import_sha512,
		.halg = {
			.digestsize = SHA384_DIGEST_SIZE,
			.statesize = sizeof(struct sha512_state),
			.base = {
				.cra_name = "sha384",
				.cra_driver_name = "sha384-sun8i-ss",
				.cra_priority = 300,
				.cra_alignmask = 3,
				.cra_flags = CRYPTO_ALG_TYPE_AHASH |
					CRYPTO_ALG_ASYNC |
					CRYPTO_ALG_NEED_FALLBACK,
				.cra_blocksize = SHA384_BLOCK_SIZE,
				.cra_ctxsize = sizeof(struct sun8i_hash_req_ctx),
				.cra_module = THIS_MODULE,
				.cra_type = &crypto_ahash_type,
				.cra_init = sun8i_hash_crainit
			}
		}
	}
},
{	.type = CRYPTO_ALG_TYPE_AHASH,
	.mode = SS_OP_SHA512,
	.hash_init = ce_sha512_init,
	.alg.hash = {
		.init = sun8i_hash_init,
		.update = sun8i_hash_update,
		.final = sun8i_hash_final,
		.finup = sun8i_hash_finup,
		.digest = sun8i_hash_digest,
		.export = sun8i_hash_export_sha512,
		.import = sun8i_hash_import_sha512,
		.halg = {
			.digestsize = SHA512_DIGEST_SIZE,
			.statesize = sizeof(struct sha512_state),
			.base = {
				.cra_name = "sha512",
				.cra_driver_name = "sha512-sun8i-ss",
				.cra_priority = 300,
				.cra_alignmask = 3,
				.cra_flags = CRYPTO_ALG_TYPE_AHASH |
					CRYPTO_ALG_ASYNC |
					CRYPTO_ALG_NEED_FALLBACK,
				.cra_blocksize = SHA512_BLOCK_SIZE,
				.cra_ctxsize = sizeof(struct sun8i_hash_req_ctx),
				.cra_module = THIS_MODULE,
				.cra_type = &crypto_ahash_type,
				.cra_init = sun8i_hash_crainit
			}
		}
	}
}

};

static int sun8i_ss_probe(struct platform_device *pdev)
{
	struct resource *res;
	u32 v;
	int err, i;
	struct sun8i_ss_ctx *ss;

	if (!pdev->dev.of_node)
		return -ENODEV;

	ss = devm_kzalloc(&pdev->dev, sizeof(*ss), GFP_KERNEL);
	if (!ss)
		return -ENOMEM;

	res = platform_get_resource(pdev, IORESOURCE_MEM, 0);
	ss->base = devm_ioremap_resource(&pdev->dev, res);
	if (IS_ERR(ss->base)) {
		err = PTR_ERR(ss->base);
		dev_err(&pdev->dev, "Cannot request MMIO %d\n", err);
		return err;
	}

	ss->busclk = devm_clk_get(&pdev->dev, "ahb1_ce");
	if (IS_ERR(ss->busclk)) {
		err = PTR_ERR(ss->busclk);
		dev_err(&pdev->dev, "Cannot get AHB SS clock err=%d\n", err);
		return err;
	}
	dev_dbg(&pdev->dev, "clock ahb_ss acquired\n");

	ss->ssclk = devm_clk_get(&pdev->dev, "mod");
	if (IS_ERR(ss->ssclk)) {
		err = PTR_ERR(ss->ssclk);
		dev_err(&pdev->dev, "Cannot get SS clock err=%d\n", err);
		return err;
	}
/*
	err = clk_set_rate(ss->busclk, 300 * 1000 * 1000);
	if (err)
		dev_err(&pdev->dev, "Cannot set SS clk\n");*/

	ss->reset = devm_reset_control_get_optional(&pdev->dev, "ahb");
	if (IS_ERR(ss->reset)) {
		if (PTR_ERR(ss->reset) == -EPROBE_DEFER)
			return PTR_ERR(ss->reset);
		dev_info(&pdev->dev, "no reset control found\n");
		ss->reset = NULL;
	}

	/* Enable both clocks */
	err = clk_prepare_enable(ss->busclk);
	if (err != 0) {
		dev_err(&pdev->dev, "Cannot prepare_enable busclk\n");
		return err;
	}

	err = clk_prepare_enable(ss->ssclk);
	if (err != 0) {
		dev_err(&pdev->dev, "Cannot prepare_enable ssclk\n");
		goto error_clk;
	}
	/* Deassert reset if we have a reset control */
	if (ss->reset) {
		err = reset_control_deassert(ss->reset);
		if (err) {
			dev_err(&pdev->dev, "Cannot deassert reset control\n");
			goto error_ssclk;
		}
	}

	ss->nsbase = ioremap(0x01c15800, 0x40);
	if (ss->nsbase) {
		v = readl(ss->nsbase + CE_CTR);
		v &= 0x07;
		dev_info(&pdev->dev, "CE_S Die ID %x\n", v);
	}

	v = readl(ss->base + CE_CTR);
	v >>= 16;
	v &= 0x07;
	dev_info(&pdev->dev, "CE_NS Die ID %x\n", v);

	ss->dev = &pdev->dev;
	platform_set_drvdata(pdev, ss);

	spin_lock_init(&ss->slock);

	mutex_init(&ss->mutex);

	for (i = 0; i < MAXCHAN; i++) {
		init_completion(&ss->chanlist[i].complete);

		ss->engines[i] = crypto_engine_alloc_init(ss->dev, 1);
		if (!ss->engines[i]) {
			dev_err(ss->dev, "Cannot request engine\n");
			goto error_engine;
		}
		ss->engines[i]->cipher_one_request = handle_cipher_request;
		ss->engines[i]->hash_one_request = handle_hash_request;
		err = crypto_engine_start(ss->engines[i]);
		if (err) {
			dev_err(ss->dev, "Cannot request engine\n");
			goto error_engine;
		}
	}
	/* Get Secure IRQ */
	ss->irq = platform_get_irq(pdev, 0);
	if (ss->irq < 0) {
		dev_err(ss->dev, "Cannot get S IRQ\n");
		goto error_clk;
	}

	err = devm_request_irq(&pdev->dev, ss->irq, ss_irq_handler, 0,
				   "sun8i-ce-s", ss);
	if (err < 0) {
		dev_err(ss->dev, "Cannot request S IRQ\n");
		goto error_clk;
	}

	/* Get Non Secure IRQ */
	ss->ns_irq = platform_get_irq(pdev, 1);
	if (ss->ns_irq < 0) {
		dev_err(ss->dev, "Cannot get NS IRQ\n");
		goto error_clk;
	}

	err = devm_request_irq(&pdev->dev, ss->ns_irq, ss_irq_handler, 0,
				   "sun8i-ce-ns", ss);
	if (err < 0) {
		dev_err(ss->dev, "Cannot request NS IRQ\n");
		goto error_clk;
	}

	for (i = 0; i < MAXCHAN; i++) {
		ss->tl[i] = dma_alloc_coherent(ss->dev, sizeof(struct ss_task),
						   &ss->ce_t_phy[i], GFP_KERNEL);
		if (!ss->tl[i]) {
			dev_err(ss->dev, "Cannot get DMA memory for task %d\n",
				i);
			err = -EINVAL;
			return err;
		}
	}

	for (i = 0; i < ARRAY_SIZE(ss_algs); i++) {
		ss_algs[i].ss = ss;
		switch (ss_algs[i].type) {
		case CRYPTO_ALG_TYPE_ABLKCIPHER:
			err = crypto_register_alg(&ss_algs[i].alg.crypto);
			if (err != 0) {
				dev_err(ss->dev, "Fail to register %s\n",
					ss_algs[i].alg.crypto.cra_name);
				goto error_alg;
			}
			break;
		case CRYPTO_ALG_TYPE_AHASH:
			err = crypto_register_ahash(&ss_algs[i].alg.hash);
			if (err != 0) {
				dev_err(ss->dev, "Fail to register %s\n",
					ss_algs[i].alg.hash.halg.base.cra_name);
				goto error_alg;
			}
			break;
		}
	}

	return 0;
error_alg:
	i--;
	for (; i >= 0; i--) {
		switch (ss_algs[i].type) {
		case CRYPTO_ALG_TYPE_ABLKCIPHER:
			crypto_unregister_alg(&ss_algs[i].alg.crypto);
			break;
		case CRYPTO_ALG_TYPE_AHASH:
			crypto_unregister_ahash(&ss_algs[i].alg.hash);
			break;
		}
	}
	if (ss->reset)
		reset_control_assert(ss->reset);
error_engine:
	while (i >= 0) {
		crypto_engine_exit(ss->engines[i]);
		i--;
	}
error_clk:
	clk_disable_unprepare(ss->ssclk);
error_ssclk:
	clk_disable_unprepare(ss->busclk);
	return err;
}

static int sun8i_ss_remove(struct platform_device *pdev)
{
	int i;
	struct sun8i_ss_ctx *ss = platform_get_drvdata(pdev);

	for (i = 0; i < ARRAY_SIZE(ss_algs); i++) {
		switch (ss_algs[i].type) {
		case CRYPTO_ALG_TYPE_ABLKCIPHER:
			crypto_unregister_alg(&ss_algs[i].alg.crypto);
			break;
		case CRYPTO_ALG_TYPE_AHASH:
			crypto_unregister_ahash(&ss_algs[i].alg.hash);
			break;
		}
	}
	for (i = 0; i < MAXCHAN; i++)
		crypto_engine_exit(ss->engines[i]);

	if (ss->reset)
		reset_control_assert(ss->reset);
	clk_disable_unprepare(ss->busclk);
	return 0;
}

static const struct of_device_id h3_ss_crypto_of_match_table[] = {
	{ .compatible = "allwinner,sun8i-h3-crypto" },
	{}
};
MODULE_DEVICE_TABLE(of, h3_ss_crypto_of_match_table);

static struct platform_driver sun8i_ss_driver = {
	.probe		  = sun8i_ss_probe,
	.remove		 = sun8i_ss_remove,
	.driver		 = {
		.name		   = "sun8i-ss",
		.of_match_table	= h3_ss_crypto_of_match_table,
	},
};

module_platform_driver(sun8i_ss_driver);

MODULE_DESCRIPTION("Allwinner Security System cryptographic accelerator");
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Corentin Labbe <clabbe.montjoie@gmail.com>");
