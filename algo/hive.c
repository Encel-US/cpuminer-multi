#include "miner.h"

#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>

#include "sha3/sph_shabal.h"
#include "sha3/sph_blake.h"
#include "sha3/sph_keccak.h"
#include "sha3/pomelo.h"



void hivehash(void *output, const void *input)
{
	sph_shabal256_context     ctx_shabal;
	sph_blake256_context      ctx_blake;
	sph_keccak256_context     ctx_keccak;


	//these uint512 in the c++ source of the client are backed by an array of uint32
	uint32_t _ALIGN(32) hashA[8], hashB[8];

	sph_shabal256_init(&ctx_shabal);
	sph_shabal256 (&ctx_shabal, input, 80);
	sph_shabal256_close (&ctx_shabal, hashA);

	POMELO(hashB, 32, hashA, 32, hashA, 32, 2, 10);
		
	sph_blake256_init(&ctx_blake);
	sph_blake256 (&ctx_blake, hashB, 32);
	sph_blake256_close(&ctx_blake, hashB);

	sph_keccak256_init(&ctx_keccak);
	sph_keccak256 (&ctx_keccak, hashB, 32);
	sph_keccak256_close(&ctx_keccak, hashB);


	memcpy(output, hashB, 32);
}

int scanhash_hive(int thr_id, uint32_t *pdata, const uint32_t *ptarget,
	uint32_t max_nonce,	uint64_t *hashes_done)
{

	const uint32_t first_nonce = pdata[19];
	uint32_t _ALIGN(32) endiandata[32];
	uint32_t nonce = first_nonce;
	volatile uint8_t *restart = &(work_restart[thr_id].restart);

	if (opt_benchmark)
		((uint32_t*)ptarget)[7] = 0x0cff;


	for (int k=0; k < 19; k++)
		be32enc(&endiandata[k], pdata[k]);



	const uint32_t Htarg = ptarget[7];






	do {
		uint32_t hash[8];


		be32enc(&endiandata[19], nonce);
		hivehash(hash, endiandata);


		if (hash[7] <= Htarg && fulltest(hash, ptarget)) {
			pdata[19] = nonce;
			*hashes_done = pdata[19] - first_nonce;
			return 1;
		}
		nonce++;

	} while (nonce < max_nonce && !(*restart));

	pdata[19] = nonce;

	*hashes_done = pdata[19] - first_nonce + 1;

	return 0;
}
