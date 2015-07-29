#include "sun4i-ss.h"

static int sun4i_ss_hwrng_init(struct hwrng *hwrng)
{
	struct sun4i_ss_ctx *ss;

	ss = container_of(hwrng, struct sun4i_ss_ctx, hwrng);
	get_random_bytes(ss->seed, SS_SEED_LEN);

	return 0;
}

static int sun4i_ss_hwrng_read(struct hwrng *hwrng, void *buf,
			       size_t max, bool wait)
{
	int i;
	u32 v;
	u32 *data = buf;
	const u32 mode = SS_OP_PRNG | SS_PRNG_CONTINUE | SS_ENABLED;
	size_t len;
	struct sun4i_ss_ctx *ss;

	ss = container_of(hwrng, struct sun4i_ss_ctx, hwrng);
	len = min_t(size_t, SS_DATA_LEN, max);

	spin_lock_bh(&ss->slock);

	writel(mode, ss->base + SS_CTL);

	/* write the seed */
	for (i = 0; i < SS_SEED_LEN / 4; i++)
		writel(ss->seed[i], ss->base + SS_KEY0 + i * 4);
	writel(mode | SS_PRNG_START, ss->base + SS_CTL);

	/* Read the random data */
	readsl(ss->base + SS_TXFIFO, data, len / 4);

	if (len % 4 > 0) {
		v = readl(ss->base + SS_TXFIFO);
		memcpy(data + len / 4, &v, len % 4);
	}

	/* Update the seed */
	for (i = 0; i < SS_SEED_LEN / 4; i++) {
		v = readl(ss->base + SS_KEY0 + i * 4);
		ss->seed[i] = v;
	}

	writel(0, ss->base + SS_CTL);
	spin_unlock_bh(&ss->slock);
	return len;
}

int sun4i_ss_hwrng_register(struct hwrng *hwrng)
{
	hwrng->name = "sun4i Security System PRNG";
	hwrng->init = sun4i_ss_hwrng_init;
	hwrng->read = sun4i_ss_hwrng_read;
	hwrng->quality = 1000;

	return hwrng_register(hwrng);
}

void sun4i_ss_hwrng_remove(struct hwrng *hwrng)
{
	hwrng_unregister(hwrng);
}
