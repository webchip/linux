#include <linux/crypto.h>
#include <crypto/hash.h>
#include <crypto/aes.h>
#include <crypto/md5.h>
#include <crypto/engine.h>
#include <linux/scatterlist.h>

#define CE_TDQ	0x00
#define CE_CTR	0x04
#define CE_ICR	0x08
#define CE_ISR	0x0C
#define CE_TLR	0x10
#define CE_TSR	0x14
#define CE_ESR	0x18
#define CE_CSSGR	0x1C
#define CE_CDSGR	0x20
#define CE_CSAR	0x24
#define CE_CDAR	0x28
#define CE_TPR	0x2C

/* Operation direction - bit 8 */
#define SS_ENCRYPTION		0
#define SS_DECRYPTION		BIT(8)

/* SS Method - bits 4-6 */
#define SS_OP_AES		0
#define SS_OP_DES		1
#define SS_OP_3DES		2
#define SS_OP_MD5		16
#define SS_OP_SHA1		17
#define SS_OP_SHA224		18
#define SS_OP_SHA256		19
#define SS_OP_SHA384		20
#define SS_OP_SHA512		21
#define SS_OP_PRNG		49

#define SS_AES_128BITS 0
#define SS_AES_192BITS 1
#define SS_AES_256BITS 2

#define SS_CBC	1

#define MAXCHAN 4

struct plop {
	u32 addr;
	u32 len;
} __packed;

struct ss_task {
	u32 t_id;
	u32 t_common_ctl;
	u32 t_sym_ctl;
	u32 t_asym_ctl;
	u32 t_key;
	u32 t_iv;
	u32 t_ctr;
	u32 t_dlen;
	struct plop t_src[8];
	struct plop t_dst[8];
	u32 next;
	u32 reserved[3];
} __packed __aligned(8);

struct sun8i_ce_chan {
	struct scatterlist *bounce_src;
	struct scatterlist *bounce_dst;
	void *bufsrc;
	void *bufdst;
	void *bounce_iv;
	void *next_iv;
	struct completion complete;
	int status;
};

struct sun8i_ss_ctx {
	void __iomem *base;
	void __iomem *nsbase;
	int irq;
	int ns_irq;
	struct clk *busclk;
	struct clk *ssclk;
	struct reset_control *reset;
	struct device *dev;
	struct resource *res;
	spinlock_t slock; /* control the use of the device */
	struct ss_task *tl[8] ____cacheline_aligned;
	dma_addr_t ce_t_phy[8] ____cacheline_aligned;
	struct completion complete;
	int l_flow_complete[8];
	struct mutex mutex;
	struct sun8i_ce_chan chanlist[MAXCHAN];
	struct crypto_engine *engines[MAXCHAN];
	int flow; /* flow to use in next request */
};

struct sun8i_cipher_req_ctx {
	u32 common;
	u32 sym;
	int flow;
};

struct sun8i_hash_req_ctx {
	struct scatterlist *sgbounce[8];
	u32 mode;
	u64 byte_count;
	u64 byte_count2;/* for sha384 sha512*/
	u32 *hash;
	char *buf[8];
	int sgflag[8];
	unsigned long blen;
	unsigned int bsize;
	int flags;
	u32 *tiv;
	int cursg;
	struct scatterlist *src_sg;
	/*struct crypto_shash *fallback_tfm;*/
	int flow;
};

struct sun8i_tfm_ctx {
	u32 *key;
	u32 keylen;
	u32 keymode;
	struct sun8i_ss_ctx *ss;
	struct crypto_blkcipher *fallback_tfm;
};

struct sun8i_ss_alg_template {
	u32 type;
	u32 mode;
	const void *hash_init;
	union {
		struct crypto_alg crypto;
		struct ahash_alg hash;
	} alg;
	struct sun8i_ss_ctx *ss;
};

int sun8i_ss_cipher(struct ablkcipher_request *areq);
int sun8i_ss_thread(void *data);
int sun8i_ce_enqueue(struct crypto_async_request *areq, u32 type);

int sun8i_hash_init(struct ahash_request *areq);
int sun8i_hash_export_md5(struct ahash_request *areq, void *out);
int sun8i_hash_import_md5(struct ahash_request *areq, const void *in);
int sun8i_hash_export_sha1(struct ahash_request *areq, void *out);
int sun8i_hash_import_sha1(struct ahash_request *areq, const void *in);
int sun8i_hash_export_sha224(struct ahash_request *areq, void *out);
int sun8i_hash_import_sha224(struct ahash_request *areq, const void *in);
int sun8i_hash_export_sha256(struct ahash_request *areq, void *out);
int sun8i_hash_import_sha256(struct ahash_request *areq, const void *in);
int sun8i_hash_export_sha512(struct ahash_request *areq, void *out);
int sun8i_hash_import_sha512(struct ahash_request *areq, const void *in);
int sun8i_hash_update(struct ahash_request *areq);
int sun8i_hash_finup(struct ahash_request *areq);
int sun8i_hash_digest(struct ahash_request *areq);
int sun8i_hash_final(struct ahash_request *areq);
int sun8i_hash_crainit(struct crypto_tfm *tfm);
int sun8i_hash_craexit(struct crypto_tfm *tfm);
int sun8i_hash(struct ahash_request *areq);

int sun8i_ss_compact(struct scatterlist *sg, unsigned int len);
int sun8i_ss_bounce_dst(struct ablkcipher_request *areq, int flow);
int sun8i_ss_bounce_src(struct ablkcipher_request *areq, int flow);

int sun8i_ss_aes_setkey(struct crypto_ablkcipher *tfm, const u8 *key,
		unsigned int keylen);
int sun8i_ss_cipher_init(struct crypto_tfm *tfm);
void sun8i_ss_cipher_exit(struct crypto_tfm *tfm);
int sun8i_ss_cbc_aes_decrypt(struct ablkcipher_request *areq);
int sun8i_ss_cbc_aes_encrypt(struct ablkcipher_request *areq);
int handle_cipher_request(struct crypto_engine *engine,
			  struct ablkcipher_request *breq);

int get_engine_number(struct sun8i_ss_ctx *ss);
