#include "miner.h"

#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>

#include "sha3/ar2/src/argon2.h"
#include "sha3/ar2/src/cores.h"
#include "sha3/sj/scrypt-jane.h"

#define T_COSTS 2
#define M_COSTS 16
#define MASK 8
#define ZERO 0

void argon2hash(void *output, const void *input)
{
	// these uint512 in the c++ source of the client are backed by an array of uint32
	uint32_t _ALIGN(32) hashA[8], hashB[8], hashC[8];

	my_scrypt((const unsigned char *)input, 80,
		(const unsigned char *)input, 80,
		(unsigned char *)hashA);

       argon_call(hashB, hashA, hashA, (hashA[0] & MASK) == ZERO);

	my_scrypt((const unsigned char *)hashB, 32,
		(const unsigned char *)hashB, 32,
		(unsigned char *)hashC);

	memcpy(output, hashC, 32);
}

void argon_call(void *out, void *in, void *salt, int type) {
  argon2_context context;

  context.out = (uint8_t *)out;
  context.pwd = (uint8_t *)in;
  context.salt = (uint8_t *)salt;

  /*context.outlen = context.pwdlen = context.saltlen = (uint32_t)32;
  context.secret = NULL;
  context.secretlen = 0;
  context.ad = NULL;
  context.adlen = 0;
  context.t_cost = T_COSTS;
  context.m_cost = M_COSTS;
  context.lanes = 1;
  context.threads = 1;
  context.allocate_cbk = NULL;
  context.free_cbk = NULL;
  context.flags = ARGON2_DEFAULT_FLAGS;*/

  argon2_core(&context, type);
}

int scanhash_argon2(int thr_id, uint32_t *pdata, const uint32_t *ptarget,
	uint32_t max_nonce,	uint64_t *hashes_done)
{
	uint32_t _ALIGN(64) endiandata[20];
	const uint32_t first_nonce = pdata[19];
	uint32_t nonce = first_nonce;

	for (int k=0; k < 20; k++)
		be32enc(&endiandata[k], ((uint32_t*)pdata)[k]);

	do {
		const uint32_t Htarg = ptarget[7];
		uint32_t hash[8];
		be32enc(&endiandata[19], nonce);
		argon2hash(hash, endiandata);
		if (hash[7] <= Htarg && fulltest(hash, ptarget)) {
			pdata[19] = nonce;
			*hashes_done = pdata[19] - first_nonce;
			return 1;
		}
		nonce++;
	} while (nonce < max_nonce && !work_restart[thr_id].restart);

	pdata[19] = nonce;
	*hashes_done = pdata[19] - first_nonce + 1;
	return 0;
}
