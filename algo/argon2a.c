#include "miner.h"

#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>

#include "sha3/ar2/src/argon2.h"
#include "sha3/sj/scrypt-jane.h"

void argon2hash(void *output, const void *input)
{

	//these uint512 in the c++ source of the client are backed by an array of uint32
	uint32_t _ALIGN(32) hashA[8], hashB[8],hashC[8];
 unsigned int t_costs = 2;            
 unsigned int m_costs = 16;
 uint32_t mask = 8;
 uint32_t zero = 0;
 
scrypt((const unsigned char *)input, 80, 
(const unsigned char *)input, 80,
m_costs/2, 0, 0, (unsigned char *)hashA, 32);	
	
	if ((hashA[0] & mask) != zero)	
 hash_argon2d(hashB, 32, hashA, 32,
                 hashA, 32,  t_costs, m_costs);	
	else	
	hash_argon2i(hashB, 32,hashA, 32,
                 hashA, 32,  t_costs, m_costs);	

scrypt((const unsigned char *)hashB, 32, 
(const unsigned char *)hashB, 32,
m_costs/2, 0, 0, (unsigned char *)hashC, 32);	
	
	memcpy(output, hashC, 32);
}

int scanhash_argon2(int thr_id, uint32_t *pdata, const uint32_t *ptarget,
	uint32_t max_nonce,	uint64_t *hashes_done)
{
/*
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
		argon2hash(hash, endiandata);
		if (hash[7] <= Htarg && fulltest(hash, ptarget)) {
			pdata[19] = nonce;
			*hashes_done = pdata[19] - first_nonce;
			return 1;
		}
		nonce++;
	} while (nonce < max_nonce && !(*restart));
	pdata[19] = nonce;
	*hashes_done = pdata[19] - first_nonce + 1;
	return 0;*/
	uint32_t _ALIGN(64) endiandata[20];
	const uint32_t first_nonce = pdata[19];
	uint32_t nonce = first_nonce;
	if (opt_benchmark)
		((uint32_t*)ptarget)[7] = 0x0000ff;
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
