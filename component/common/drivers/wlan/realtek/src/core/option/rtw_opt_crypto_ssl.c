#include "platform_opts.h"
#include "rtw_opt_crypto_ssl.h"
#include "osdep_service.h"

#if CONFIG_USE_MBEDTLS
/****************************************************************************************************


                        Function of Initialization


****************************************************************************************************/
int rtw_platform_set_calloc_free( void * (*calloc_func)( size_t, size_t ),
                              void (*free_func)( void * ) )
{
	mbedtls_platform_set_calloc_free(calloc_func, free_func);
}
/****************************************************************************************************


                        Function of ECC Algorithm


****************************************************************************************************/
static const unsigned char secp224r1_a[]={ 
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE, 
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFE};

//***************************************************************************************************
// \brief           initialization of ecp curve with group id
//
// \param ecc       pointer of ecc curve structure
// \param group_id  group_id defined by spec 12.4
//
// \return         0  if successful,
//                 -1 if group_id is not supported
//***************************************************************************************************
int rtw_crypto_ecc_init(sae_ecc_crypto *ecc,unsigned char group_id)
{
	int ret = 0;
	mbedtls_ecp_group_init(ecc);
	switch (group_id){
		case 19:
		      mbedtls_ecp_group_load( ecc, MBEDTLS_ECP_DP_SECP256R1);
			  mbedtls_mpi_init(&ecc->A);
			  mbedtls_mpi_copy(&ecc->A,&ecc->P);
			  mbedtls_mpi_set_bit(&ecc->A,0,0);
			  mbedtls_mpi_set_bit(&ecc->A,1,0);
			  break;
		case 20:
	 		  mbedtls_ecp_group_load( ecc, MBEDTLS_ECP_DP_SECP384R1);
			  mbedtls_mpi_init(&ecc->A);
			  mbedtls_mpi_copy(&ecc->A,&ecc->P);
			  mbedtls_mpi_set_bit(&ecc->A,0,0);
			  mbedtls_mpi_set_bit(&ecc->A,1,0);
			  break;
		case 21:
			  mbedtls_ecp_group_load( ecc, MBEDTLS_ECP_DP_SECP521R1);
			  mbedtls_mpi_init(&ecc->A);
			  mbedtls_mpi_copy(&ecc->A,&ecc->P);
			  mbedtls_mpi_set_bit(&ecc->A,0,0);
			  mbedtls_mpi_set_bit(&ecc->A,1,0);
			  break;
		case 25:
			  mbedtls_ecp_group_load( ecc, MBEDTLS_ECP_DP_SECP192R1);
			  mbedtls_mpi_init(&ecc->A);
			  mbedtls_mpi_copy(&ecc->A,&ecc->P);
			  mbedtls_mpi_set_bit(&ecc->A,0,0);
			  mbedtls_mpi_set_bit(&ecc->A,1,0);
			  break;
		case 26:
			  mbedtls_ecp_group_load( ecc, MBEDTLS_ECP_DP_SECP224R1);
			  mbedtls_mpi_init(&ecc->A);
			  mbedtls_mpi_read_binary(&ecc->A,secp224r1_a,28);
			  break;
		default:
			  printf("\r\nmbedtls_ecc_init: no available ecc type: %d \n",group_id);
			  ret = -1;
			  break;
	}
	return ret;
}

//***************************************************************************************************
// \brief           free of ecp curve
//
// \param ecc       pointer of ecc curve structure
//
// \return          void
//
//***************************************************************************************************
void rtw_crypto_ecc_free(sae_ecc_crypto *ecc)
{
	mbedtls_mpi_free(&ecc->A);
	mbedtls_ecp_group_free(ecc);
}

//***************************************************************************************************
// \brief            get Parameter A of ECC
//
// \param ecc        pointer of ecc curve structure
// \param a          pointer of big number of a 
//
// \return  		 0 if successful
//                   -1 if fail
//
//***************************************************************************************************
int rtw_crypto_ecc_get_param_a(sae_ecc_crypto *ecc, sae_crypto_bignum *a)
{
	int ret = 0;
	if((ecc == NULL) || (a == NULL)){
		ret = -1;
		return ret;
	}

	MBEDTLS_MPI_CHK(mbedtls_mpi_copy(a,&ecc->A));

cleanup:	
	return ret;
}


//***************************************************************************************************
// \brief           get Parameter B of ECC
//
// \param ecc        pointer of ecc curve structure
// \param a          pointer of big number of a 
//
// \return  		0 if successful
//                  -1 if fail
//
//***************************************************************************************************
int rtw_crypto_ecc_get_param_b(sae_ecc_crypto *ecc, sae_crypto_bignum *b)
{
	int ret = 0;
	if((ecc == NULL) || (b == NULL)){
		ret = -1;
		return ret;
	}

	MBEDTLS_MPI_CHK(mbedtls_mpi_copy(b,&ecc->B));

cleanup:	
	return ret;
}

//***************************************************************************************************
// \brief           get Order of ECC
//
// \param ecc        pointer of ecc curve structure
// \param n          pointer of big number of a 
//
// \return  		0 if successful
//                  -1 if fail
//
//***************************************************************************************************
int rtw_crypto_ecc_get_param_order(sae_ecc_crypto *ecc, sae_crypto_bignum *n)
{
	int ret = 0;
	if((ecc == NULL) || (n == NULL)){
		ret = -1;
		return ret;
	}

	MBEDTLS_MPI_CHK(mbedtls_mpi_copy(n,&ecc->N));

cleanup:	
	return ret;
}


//***************************************************************************************************
// \brief           get Parameter B of ECC
//
// \param ecc        pointer of ecc curve structure
// \param a          pointer of big number of a 
//
// \return  		0 if successful
//                  -1 if fail
//
//***************************************************************************************************
int rtw_crypto_ecc_get_param_prime(sae_ecc_crypto *ecc, sae_crypto_bignum *prime)
{
	int ret = 0;
	if((ecc == NULL) || (prime == NULL)){
		ret = -1;
		return ret;
	}
	
	MBEDTLS_MPI_CHK(mbedtls_mpi_copy(prime,&ecc->P));

cleanup:	
	return ret;
}


/*********************************************************************************************
// \brief:     import point from bignum

// \param ecc: pointer of ecc
// \param x:   input point x
// \param y:   input point y 
// \param p:   import point
//          
return:    0 if successful
		   -1 if failed
*********************************************************************************************/
int rtw_crypto_ecc_point_read_bignum(sae_ecc_crypto *ecc,sae_crypto_bignum *x,sae_crypto_bignum *y,sae_ecc_point *p)
{
	int ret = 0;
	unsigned char *buf = NULL;
	unsigned int buf_len;
	unsigned int prime_len;

	if((ecc == NULL) || (x == NULL) || (y == NULL) || (p == NULL)){
		ret = -1;
		goto cleanup;
	}

	prime_len = mbedtls_mpi_size(&ecc->P);
	
	buf_len = 2*prime_len + 1;

	buf = rtw_zmalloc(buf_len);

	if(buf == NULL){
		ret = -1;
		goto cleanup;
	}

	buf[0] = 0x04;
	
	if(rtw_crypto_bignum_write_binary(x,buf + 1,prime_len) < 0){
		ret = -1;
		goto cleanup;
	}

	if(rtw_crypto_bignum_write_binary(y,buf + 1 + prime_len,prime_len) < 0){
		ret = -1;
		goto cleanup;
	}

	ret = mbedtls_ecp_point_read_binary(ecc,p,buf,buf_len);

		
cleanup:
	if(buf)
		rtw_mfree(buf,buf_len);
	return ret;
	
}

/*********************************************************************************************
brief:     export point to bignum 

Parameter: ecc: pointer of ecc
           x:  output point x
           y:  output point y
           p:  export point of ecc
           
return:    0 if successful
		   -1 if failed
*********************************************************************************************/
int rtw_crypto_ecc_point_write_bignum(sae_ecc_crypto *ecc,sae_crypto_bignum *x,sae_crypto_bignum *y,sae_ecc_point *p)
{
	int ret = 0;
	unsigned char *buf = NULL;
	unsigned int buf_len;
	unsigned int prime_len;
	unsigned int out_len = 0;


	if((ecc == NULL) || (x == NULL) || (y == NULL) || (p == NULL)){
		ret = -1;
		goto cleanup;
	}

	prime_len = mbedtls_mpi_size(&ecc->P);

	buf_len = 2*prime_len + 1;

	buf = rtw_zmalloc(buf_len);

	if(buf == NULL){
		ret = -1;
		goto cleanup;
	}

	if(mbedtls_ecp_point_write_binary(ecc,p,MBEDTLS_ECP_PF_UNCOMPRESSED,&out_len,buf,buf_len) <0 ){
		ret = -1;
		goto cleanup;
	}

	if(rtw_crypto_bignum_read_binary(x,buf + 1, prime_len) < 0){
		ret = -1;
		goto cleanup;
	}
	
	
	if(rtw_crypto_bignum_read_binary(y,buf + 1 + prime_len, prime_len) < 0){
		ret = -1;
		goto cleanup;
	}
	
		
cleanup:
	if(buf)
		rtw_mfree(buf,buf_len);
	return ret;
	
}


//***************************************************************************************************
// \brief			Initialize one ecc point
//
// \param point		pointer to ecc point
//
// \return			void
//					
//***************************************************************************************************
void rtw_crypto_ecc_point_init(sae_ecc_point *point)
{
	mbedtls_ecp_point_init(point);
}

//***************************************************************************************************
// \brief			Free one ecc point
//
// \param point		pointer to ecc point
//
// \return			void
//					
//***************************************************************************************************
void rtw_crypto_ecc_point_free(sae_ecc_point *point)
{
	mbedtls_ecp_point_free(point);
}

//***************************************************************************************************
// \brief			check the ecc point is the infinity point
//
// \param point		pointer to ecc point
//
// \return			0  none-infinity 
//					1  infinity				
//***************************************************************************************************
int rtw_crypto_ecc_point_is_at_infinity(sae_ecc_point *point)
{
	return mbedtls_ecp_is_zero(point);
}

//***************************************************************************************************
// \brief			R = m * P 
//
// \param ecc		pointer of ecc curve structure
// \param R			pointer to the result ecc point
// \param m			pointer to a bignum
// \param P         pointer to the source 
// \return			0  success
//					-1 fail
//***************************************************************************************************
int rtw_crypto_ecc_point_mul_bignum(sae_ecc_crypto *ecc,sae_ecc_point *R,sae_crypto_bignum *m,sae_ecc_point *P)
{
	int ret = 0;	
	MBEDTLS_MPI_CHK( mbedtls_ecp_mul( ecc, R, m, P, NULL, NULL ));
cleanup:
	if(ret < 0)
		ret = -1;
	return ret;
}

//***************************************************************************************************
// \brief			justify if the ecc point is on the curve
//
// \param ecc		pointer of ecc curve structure
// \param P         pointer to the ecc point 

// \return			0  yes
//					-1 no 
//***************************************************************************************************
int rtw_crypto_ecc_point_is_on_curve(sae_ecc_crypto *ecc,sae_ecc_point *P)
{
	int ret = 0;	

	MBEDTLS_MPI_CHK(mbedtls_ecp_check_pubkey(ecc,P));

cleanup:	
	if(ret < 0)
		ret = -1;
	return ret;
}


//***************************************************************************************************
// \brief			X = A + B 
//
// \param ecc		pointer of ecc curve structure
// \param X			pointer of destination point
// \param A			pointer of left hand point
// \param B         pointer of right hand point
//
// \return			0  success
//					-1 fail
//***************************************************************************************************
int rtw_crypto_ecc_point_add_point(sae_ecc_crypto *ecc,sae_ecc_point *X,sae_ecc_point *A,sae_ecc_point *B)
{
	int ret = 0;
	mbedtls_mpi one;

	mbedtls_mpi_init(&one);
	
    MBEDTLS_MPI_CHK(mbedtls_mpi_lset(&one,1));
    MBEDTLS_MPI_CHK(mbedtls_ecp_muladd(ecc,X,&one,A,&one,B));

cleanup:
	if(ret < 0)
		ret = -1;
	mbedtls_mpi_free(&one);
	return ret;
}

//***************************************************************************************************
// \brief			compare two ecc points
//
// \param ecc		pointer of ecc curve structure
// \param P1		pointer of left hand point
// \param P2        pointer of right hand point
//
// \return			0  P1 = P2
//					<0 P1 != P2
//***************************************************************************************************
int rtw_crypto_ecc_point_cmp(sae_ecc_point *P1,sae_ecc_point *P2)
{
	return mbedtls_ecp_point_cmp(P1,P2);
}


/****************************************************************************************************


                        Function of Big number Operation and computation
                        

****************************************************************************************************/


//***************************************************************************************************
// \brief			Initialize one Big number
//                  This just makes it ready to be set or freed, but does not define a value for the MPI
//
// \param X		    pointer of one big number to be initialized
//
// \return			void					
//
//***************************************************************************************************
void rtw_crypto_bignum_init(sae_crypto_bignum *X)
{
	mbedtls_mpi_init(X);
}

void rtw_crypto_bignum_init_set(sae_crypto_bignum *X, const u8 *buf, size_t len)
{
	mbedtls_mpi_init(X);
	mbedtls_mpi_read_binary(X, buf, len);
}

void rtw_crypto_bignum_init_int(sae_crypto_bignum *X, int val)
{
	mbedtls_mpi_init(X);
	mbedtls_mpi_lset(X,val);
}

//***************************************************************************************************
// \brief			unallocate one big number
//
// \param X		    pointer of big number to be unallocated
//
// \return			void					
//
//***************************************************************************************************
void rtw_crypto_bignum_free(sae_crypto_bignum *X)
{
	mbedtls_mpi_free(X);
}

//***************************************************************************************************
// \brief			Copy the contents of Y into X
//
// \param X		    pointer of destination big number
// \param Y			pointer of source big number
//
// \return			0 if successful
//					-1 if failed
//
//***************************************************************************************************
int rtw_crypto_bignum_copy(sae_crypto_bignum *X,sae_crypto_bignum *Y)
{
	int ret = 0;
	MBEDTLS_MPI_CHK(mbedtls_mpi_copy(X,Y));
	
cleanup:
	if((ret) < 0)
		ret = -1;
	return ret;
}


//***************************************************************************************************
// \brief			Return the number of bits up to and including the most significant '1' bit'
//
// \param X		    pointer of big number to use
//
// \return			length of bit					
//
//***************************************************************************************************
size_t rtw_crypto_bignum_bitlen(sae_crypto_bignum *X)
{
	return mbedtls_mpi_bitlen(X);
}


//***************************************************************************************************
// \brief			Get a specific bit from X
//
// \param X		    pointer of big number to use
// \param pos		Zero-based index of the bit in X
//
// \return			either 0 or 1					
//
//***************************************************************************************************
size_t rtw_crypto_bignum_get_bit(sae_crypto_bignum *X,size_t pos)
{
	return mbedtls_mpi_get_bit(X,pos);
}


//***************************************************************************************************
// \brief			return the total size in bytes
//
// \param X		    pointer of big number to use
//
// \return			total size of big number in bytes				
//
//***************************************************************************************************
size_t rtw_crypto_bignum_size(sae_crypto_bignum *X)
{
	return mbedtls_mpi_size(X);
}


//***************************************************************************************************
// \brief			Import X from unsigned binary data, big endian
//
// \param X		    pointer of destination big number
// \param buf		pointer of input buffer
// \param buf_len   input buffer size
//
// \return			0 if successful				
//					-1 if failed
//
//***************************************************************************************************
int rtw_crypto_bignum_read_binary(sae_crypto_bignum *X,const unsigned char *buf, size_t buf_len)
{
	int ret = 0;
	MBEDTLS_MPI_CHK(mbedtls_mpi_read_binary(X,buf,buf_len));
		
cleanup:		
	if((ret)<0)
		ret = -1;

	return ret;
}


//***************************************************************************************************
// \brief			 Export X into unsigned binary data, big endian.
//					 Always fills the whole buffer, which will start with zeros if the number is smaller.
//
// \param X		    pointer of source big number
// \param buf		pointer of output buffer
// \param buf_len   output buffer size
//
// \return			0 if successful				
//					-1 if failed
//
//***************************************************************************************************
int rtw_crypto_bignum_write_binary(sae_crypto_bignum *X,unsigned char *buf, size_t buf_len)
{
	int ret = 0;
	MBEDTLS_MPI_CHK(mbedtls_mpi_write_binary(X,buf,buf_len));
		
cleanup:		
	if((ret)<0)
		ret = -1;

	return ret;
}

//***************************************************************************************************
// \brief			 Right-shift: X >>= count
//
// \param X		    pointer of big number to shift
// \param count		amount to shift
//
// \return			0 if successful				
//					-1 if failed
//
//***************************************************************************************************
int rtw_crypto_bignum_shift_r(sae_crypto_bignum *X,size_t count)
{
	int ret = 0;
	MBEDTLS_MPI_CHK(mbedtls_mpi_shift_r(X,count));
		
cleanup:		
	if((ret)<0)
		ret = -1;

	return ret;
}

//***************************************************************************************************
// \brief			Compare signed values
//
// \param X		    pointer of left hand big number
// \param Y		    pointer of right hand big number
//
// \return			1 if X is greater than Y				
//					-1 if X is lesser than Y
//					0 if X is equal to Y
//
//***************************************************************************************************
int rtw_crypto_bignum_cmp_bignum(sae_crypto_bignum *X,sae_crypto_bignum *Y)
{
	return mbedtls_mpi_cmp_mpi(X,Y);
}

//***************************************************************************************************
// \brief			Compare signed values
//
// \param X		    pointer of left hand big number
// \param z		    The integer value to compare to
//
// \return			1 if X is greater than z				
//					-1 if X is lesser than z
//					0 if X is equal to z
//
//***************************************************************************************************
int rtw_crypto_bignum_cmp_int(sae_crypto_bignum *X,int z)
{
	return mbedtls_mpi_cmp_int(X,z);
}

//***************************************************************************************************
// \brief			Signed addition:X = A + B
//
// \param X		    pointer of destination big number
// \param A		    pointer of left hand big number
// \param B			pointer of right hand big number
//
// \return			0 if successful					
//					-1 if failed
//
//***************************************************************************************************
int rtw_crypto_bignum_add_bignum(sae_crypto_bignum *X,sae_crypto_bignum *A,sae_crypto_bignum *B)
{
	int ret = 0;
	MBEDTLS_MPI_CHK(mbedtls_mpi_add_mpi(X,A,B));
		
cleanup:		
	if((ret)<0)
		ret = -1;

	return ret;
}


//***************************************************************************************************
// \brief			Signed addition: X = A + b
//
// \param X		    pointer of destination big number
// \param A		    pointer of left hand big number
// \param b			The integer value to add
//
// \return			0 if successful					
//					-1 if failed
//
//***************************************************************************************************
int rtw_crypto_bignum_add_int(sae_crypto_bignum *X,sae_crypto_bignum *A,int b)
{
	int ret = 0;
	MBEDTLS_MPI_CHK(mbedtls_mpi_add_int(X,A,b));
		
cleanup:		
	if((ret)<0)
		ret = -1;

	return ret;
}

//***************************************************************************************************
// \brief			Signed addition: X = A - B
//
// \param X		    pointer of destination big number
// \param A		    pointer of left hand big number
// \param B			pointer of right hand big number
//
// \return			0 if successful					
//					-1 if failed
//
//***************************************************************************************************
int rtw_crypto_bignum_sub_bignum(sae_crypto_bignum *X,sae_crypto_bignum *A,sae_crypto_bignum *B)
{
	int ret = 0;
	MBEDTLS_MPI_CHK(mbedtls_mpi_sub_mpi(X,A,B));
		
cleanup:		
	if((ret)<0)
		ret = -1;

	return ret;
}


//***************************************************************************************************
// \brief			Signed addition: X = A - b
//
// \param X		    point of destination big number
// \param A		    point of left hand big number
// \param b			The integer value to subtract
//
// \return			0 if successful					
//					-1 if failed
//
//***************************************************************************************************
int rtw_crypto_bignum_sub_int(sae_crypto_bignum *X,sae_crypto_bignum *A,int b)
{
	int ret = 0;
	MBEDTLS_MPI_CHK(mbedtls_mpi_sub_int(X,A,b));
		
cleanup:		
	if((ret)<0)
		ret = -1;

	return ret;
}

//***************************************************************************************************
// \brief			Division by big number: A = Q * B + R
//
// \param Q		    pointer of destination big number for the quotient
// \param R		    pointer of destination big number for the rest value
// \param A			pointer of left hand big number
// \param B			pointer of right hand big number
//
// \return			0 if successful					
//					-1 if failed
// 
// \note 			Either Q or R can be NULL.
//***************************************************************************************************
int rtw_crypto_bignum_div_bignum(sae_crypto_bignum *Q,sae_crypto_bignum *R,sae_crypto_bignum *A,sae_crypto_bignum *B)
{
	int ret = 0;
	MBEDTLS_MPI_CHK(mbedtls_mpi_div_mpi(Q,R,A,B));
		
cleanup:		
	if((ret)<0)
		ret = -1;

	return ret;
}


//***************************************************************************************************
// \brief			X = A mod N
//
// \param X		    pointer of destination big number
// \param A		    pointer of left hand big number
// \param N			pointer of modular big number
//
// \return			0 if successful					
//					-1 if failed
//
//***************************************************************************************************
int rtw_crypto_bignum_mod_bignum(sae_crypto_bignum *X,sae_crypto_bignum *A,sae_crypto_bignum *N)
{
	int ret = 0;
	MBEDTLS_MPI_CHK(mbedtls_mpi_mod_mpi(X,A,N));
		
cleanup:		
	if((ret)<0)
		ret = -1;

	return ret;
}

//***************************************************************************************************
// \brief			X = (A + B) mod N
//
// \param X		    pointer of destination big number
// \param A		    pointer of left hand big number
// \param B 		pointer of right hand big number
// \param N			pointer of modular big number
//
// \return			0 if successful					
//					-1 if failed
//
//***************************************************************************************************
int rtw_crypto_bignum_add_mod(sae_crypto_bignum *X,sae_crypto_bignum *A,sae_crypto_bignum *B,sae_crypto_bignum *N)
{
	int ret = 0;
	MBEDTLS_MPI_CHK(mbedtls_mpi_add_mpi(X,A,B));
	MBEDTLS_MPI_CHK(mbedtls_mpi_mod_mpi(X,X,N));
		
cleanup:		
	if((ret)<0)
		ret = -1;

	return ret;
}

//***************************************************************************************************
// \brief			X = (A * B) mod N
//
// \param X		    pointer of destination big number
// \param A		    pointer of left hand big number
// \param B 		pointer of right hand big number
// \param N			pointer of modular big number
//
// \return			0 if successful					
//					-1 if failed
//
//***************************************************************************************************
int rtw_crypto_bignum_mul_mod(sae_crypto_bignum *X,sae_crypto_bignum *A,sae_crypto_bignum *B,sae_crypto_bignum *N)
{
	int ret = 0;
	MBEDTLS_MPI_CHK(mbedtls_mpi_mul_mpi(X,A,B));
	MBEDTLS_MPI_CHK(mbedtls_mpi_mod_mpi(X,X,N));
		
cleanup:		
	if((ret)<0)
		ret = -1;

	return ret;
}

//***************************************************************************************************
// \brief			X = (A ^ B) mod N
//
// \param X		    pointer of destination big number
// \param A		    pointer of left hand big number
// \param B 		pointer of right hand big number
// \param N			pointer of modular big number
//
// \return			0 if successful					
//					-1 if failed
//
//***************************************************************************************************
int rtw_crypto_bignum_exp_mod(sae_crypto_bignum *X,sae_crypto_bignum *A,sae_crypto_bignum *B,sae_crypto_bignum *N)
{
	int ret = 0;
	MBEDTLS_MPI_CHK(mbedtls_mpi_exp_mod(X,A,B,N,NULL));
		
cleanup:		
	if((ret)<0)
		ret = -1;

	return ret;
}


//***************************************************************************************************
// \brief		assign Y ==> X
//
// \param X     pointer to bignum X
// \param Y		pointer to bignum Y
// \param inv   assign or not
//
// \return		0 if successful
//				-1 if failed				
//***************************************************************************************************
int rtw_crypto_bignum_assign(sae_crypto_bignum *X, sae_crypto_bignum *Y,unsigned char inv)
{
	int ret = 0;

	MBEDTLS_MPI_CHK(mbedtls_mpi_safe_cond_assign(X,Y,inv));
		
cleanup:
	if(ret < 0)
		ret = -1;
	return ret;
}

//***************************************************************************************************
// \brief		X = A^-1 mod N
//
// \param X     pointer to bignum X
// \param Y		pointer to bignum Y
// \param inv   assign or not
//
// \return		0 if successful
//				-1 if failed				
//***************************************************************************************************
int rtw_crypto_bignum_inverse(sae_crypto_bignum *X, sae_crypto_bignum *A,sae_crypto_bignum *N)
{
	int ret = 0;

	MBEDTLS_MPI_CHK(mbedtls_mpi_inv_mod(X,A,N));
		
cleanup:
	if(ret < 0)
		ret = -1;
	return ret;
}

int crypto_ec_point_from_bin(unsigned int prime_len, u8 *val, sae_ecc_point *point)
{
	int ret = 0;

	if (rtw_crypto_bignum_read_binary(&point->X, val, prime_len) < 0){
		ret=-1;
		goto cleanup;
	}

	if (rtw_crypto_bignum_read_binary(&point->Y, val + prime_len, prime_len) < 0){
		ret=-1;
		goto cleanup;
	}
	rtw_crypto_bignum_init_int(&point->Z, 1);

cleanup:
	return ret;
}

int crypto_ec_point_to_bin(unsigned int prime_len, sae_ecc_point *point, u8 *x, u8 *y)
{
	if (x) {
		if (rtw_crypto_bignum_write_binary(&point->X, x, prime_len) < 0)
			return -1;
	}

	if (y) {
		if (rtw_crypto_bignum_write_binary(&point->Y, y, prime_len) < 0)
			return -1;
	}

	return 0;
}

#elif CONFIG_USE_POLARSSL
/************************************************************
*
*1.sync typedef and define in ecp.c(rom)
*
************************************************************/
/*
 * Curve types: internal for now, might be exposed later
 */
typedef enum
{
    POLARSSL_ECP_TYPE_NONE = 0,
    POLARSSL_ECP_TYPE_SHORT_WEIERSTRASS,    /* y^2 = x^3 + a x + b      */
    POLARSSL_ECP_TYPE_MONTGOMERY,           /* y^2 = x^3 + a x^2 + x    */
} ecp_curve_type;

#define MOD_MUL( N )    do { MPI_CHK( ecp_modp_patch( &N, grp ) ); INC_MUL_COUNT } \
                        while( 0 )

/*
 * Reduce a mpi mod p in-place, to use after mpi_sub_mpi
 * N->s < 0 is a very fast test, which fails only if N is 0
 */
#define MOD_SUB( N )                                \
    while( N.s < 0 && mpi_cmp_int( &N, 0 ) != 0 )   \
        MPI_CHK( mpi_add_mpi( &N, &N, &grp->P ) )

/*
 * Reduce a mpi mod p in-place, to use after mpi_add_mpi and mpi_mul_int.
 * We known P, N and the result are positive, so sub_abs is correct, and
 * a bit faster.
 */
#define MOD_ADD( N )                                \
    while( mpi_cmp_mpi( &N, &grp->P ) >= 0 )        \
        MPI_CHK( mpi_sub_abs( &N, &N, &grp->P ) )

#if defined(POLARSSL_SELF_TEST)
#define INC_MUL_COUNT   mul_count++;
#else
#define INC_MUL_COUNT
#endif

/************************************************************
*
*2.sync functions that static in ecp.c(rom).
*
************************************************************/
/*
 * Wrapper around fast quasi-modp functions, with fall-back to mpi_mod_mpi.
 * See the documentation of struct ecp_group.
 *
 * This function is in the critial loop for ecp_mul, so pay attention to perf.
 */
static int ecp_modp_patch( mpi *N, const ecp_group *grp )
{
    int ret;

    if( grp->modp == NULL )
        return( mpi_mod_mpi( N, N, &grp->P ) );

    /* N->s < 0 is a much faster test, which fails only if N is 0 */
    if( ( N->s < 0 && mpi_cmp_int( N, 0 ) != 0 ) ||
        mpi_msb( N ) > 2 * grp->pbits )
    {
        return( POLARSSL_ERR_ECP_BAD_INPUT_DATA );
    }

    MPI_CHK( grp->modp( N ) );

    /* N->s < 0 is a much faster test, which fails only if N is 0 */
    while( N->s < 0 && mpi_cmp_int( N, 0 ) != 0 )
        MPI_CHK( mpi_add_mpi( N, N, &grp->P ) );

    while( mpi_cmp_mpi( N, &grp->P ) >= 0 )
        /* we known P, N and the result are positive */
        MPI_CHK( mpi_sub_abs( N, N, &grp->P ) );

cleanup:
    return( ret );
}
static ecp_curve_type ecp_get_type_patch( const ecp_group *grp )
{
    if( grp->G.X.p == NULL )
        return( POLARSSL_ECP_TYPE_NONE );

    if( grp->G.Y.p == NULL )
        return( POLARSSL_ECP_TYPE_MONTGOMERY );
    else
        return( POLARSSL_ECP_TYPE_SHORT_WEIERSTRASS );
}
/*
 * For curves in short Weierstrass form, we do all the internal operations in
 * Jacobian coordinates.
 *
 * For multiplication, we'll use a comb method with coutermeasueres against
 * SPA, hence timing attacks.
 */

/*
 * Normalize jacobian coordinates so that Z == 0 || Z == 1  (GECC 3.2.1)
 * Cost: 1N := 1I + 3M + 1S
 */
static int ecp_normalize_jac_patch( const ecp_group *grp, ecp_point *pt )
{
    int ret;
    mpi Zi, ZZi;

    if( mpi_cmp_int( &pt->Z, 0 ) == 0 )
        return( 0 );

    mpi_init( &Zi ); mpi_init( &ZZi );

    /*
     * X = X / Z^2  mod p
     */
    MPI_CHK( mpi_inv_mod( &Zi,      &pt->Z,     &grp->P ) );
    MPI_CHK( mpi_mul_mpi( &ZZi,     &Zi,        &Zi     ) ); MOD_MUL( ZZi );
    MPI_CHK( mpi_mul_mpi( &pt->X,   &pt->X,     &ZZi    ) ); MOD_MUL( pt->X );

    /*
     * Y = Y / Z^3  mod p
     */
    MPI_CHK( mpi_mul_mpi( &pt->Y,   &pt->Y,     &ZZi    ) ); MOD_MUL( pt->Y );
    MPI_CHK( mpi_mul_mpi( &pt->Y,   &pt->Y,     &Zi     ) ); MOD_MUL( pt->Y );

    /*
     * Z = 1
     */
    MPI_CHK( mpi_lset( &pt->Z, 1 ) );

cleanup:

    mpi_free( &Zi ); mpi_free( &ZZi );

    return( ret );
}

/*
 * Point doubling R = 2 P, Jacobian coordinates
 *
 * http://www.hyperelliptic.org/EFD/g1p/auto-code/shortw/jacobian/doubling/dbl-2007-bl.op3
 * with heavy variable renaming, some reordering and one minor modification
 * (a = 2 * b, c = d - 2a replaced with c = d, c = c - b, c = c - b)
 * in order to use a lot less intermediate variables (6 vs 25).
 *
 * Cost: 1D := 2M + 8S
 */
static int ecp_double_jac_patch( const ecp_group *grp, ecp_point *R,
                           const ecp_point *P )
{
    int ret;
    mpi T1, T2, T3, X3, Y3, Z3;

#if defined(POLARSSL_SELF_TEST)
    dbl_count++;
#endif

    mpi_init( &T1 ); mpi_init( &T2 ); mpi_init( &T3 );
    mpi_init( &X3 ); mpi_init( &Y3 ); mpi_init( &Z3 );

    MPI_CHK( mpi_mul_mpi( &T3,  &P->X,  &P->X   ) ); MOD_MUL( T3 );
    MPI_CHK( mpi_mul_mpi( &T2,  &P->Y,  &P->Y   ) ); MOD_MUL( T2 );
    MPI_CHK( mpi_mul_mpi( &Y3,  &T2,    &T2     ) ); MOD_MUL( Y3 );
    MPI_CHK( mpi_add_mpi( &X3,  &P->X,  &T2     ) ); MOD_ADD( X3 );
    MPI_CHK( mpi_mul_mpi( &X3,  &X3,    &X3     ) ); MOD_MUL( X3 );
    MPI_CHK( mpi_sub_mpi( &X3,  &X3,    &Y3     ) ); MOD_SUB( X3 );
    MPI_CHK( mpi_sub_mpi( &X3,  &X3,    &T3     ) ); MOD_SUB( X3 );
    MPI_CHK( mpi_mul_int( &T1,  &X3,    2       ) ); MOD_ADD( T1 );
    MPI_CHK( mpi_mul_mpi( &Z3,  &P->Z,  &P->Z   ) ); MOD_MUL( Z3 );
    MPI_CHK( mpi_mul_mpi( &X3,  &Z3,    &Z3     ) ); MOD_MUL( X3 );
    MPI_CHK( mpi_mul_int( &T3,  &T3,    3       ) ); MOD_ADD( T3 );

    /* Special case for A = -3 */
    if( grp->A.p == NULL )
    {
        MPI_CHK( mpi_mul_int( &X3, &X3, 3 ) );
        X3.s = -1; /* mpi_mul_int doesn't handle negative numbers */
        MOD_SUB( X3 );
    }
    else
        MPI_CHK( mpi_mul_mpi( &X3,  &X3,    &grp->A ) ); MOD_MUL( X3 );

    MPI_CHK( mpi_add_mpi( &T3,  &T3,    &X3     ) ); MOD_ADD( T3 );
    MPI_CHK( mpi_mul_mpi( &X3,  &T3,    &T3     ) ); MOD_MUL( X3 );
    MPI_CHK( mpi_sub_mpi( &X3,  &X3,    &T1     ) ); MOD_SUB( X3 );
    MPI_CHK( mpi_sub_mpi( &X3,  &X3,    &T1     ) ); MOD_SUB( X3 );
    MPI_CHK( mpi_sub_mpi( &T1,  &T1,    &X3     ) ); MOD_SUB( T1 );
    MPI_CHK( mpi_mul_mpi( &T1,  &T3,    &T1     ) ); MOD_MUL( T1 );
    MPI_CHK( mpi_mul_int( &T3,  &Y3,    8       ) ); MOD_ADD( T3 );
    MPI_CHK( mpi_sub_mpi( &Y3,  &T1,    &T3     ) ); MOD_SUB( Y3 );
    MPI_CHK( mpi_add_mpi( &T1,  &P->Y,  &P->Z   ) ); MOD_ADD( T1 );
    MPI_CHK( mpi_mul_mpi( &T1,  &T1,    &T1     ) ); MOD_MUL( T1 );
    MPI_CHK( mpi_sub_mpi( &T1,  &T1,    &T2     ) ); MOD_SUB( T1 );
    MPI_CHK( mpi_sub_mpi( &Z3,  &T1,    &Z3     ) ); MOD_SUB( Z3 );

    MPI_CHK( mpi_copy( &R->X, &X3 ) );
    MPI_CHK( mpi_copy( &R->Y, &Y3 ) );
    MPI_CHK( mpi_copy( &R->Z, &Z3 ) );

cleanup:
    mpi_free( &T1 ); mpi_free( &T2 ); mpi_free( &T3 );
    mpi_free( &X3 ); mpi_free( &Y3 ); mpi_free( &Z3 );

    return( ret );
}

/*
 * Addition: R = P + Q, mixed affine-Jacobian coordinates (GECC 3.22)
 *
 * The coordinates of Q must be normalized (= affine),
 * but those of P don't need to. R is not normalized.
 *
 * Special cases: (1) P or Q is zero, (2) R is zero, (3) P == Q.
 * None of these cases can happen as intermediate step in ecp_mul_comb():
 * - at each step, P, Q and R are multiples of the base point, the factor
 *   being less than its order, so none of them is zero;
 * - Q is an odd multiple of the base point, P an even multiple,
 *   due to the choice of precomputed points in the modified comb method.
 * So branches for these cases do not leak secret information.
 *
 * We accept Q->Z being unset (saving memory in tables) as meaning 1.
 *
 * Cost: 1A := 8M + 3S
 */
static int ecp_add_mixed_patch( const ecp_group *grp, ecp_point *R,
                          const ecp_point *P, const ecp_point *Q )
{
    int ret;
    mpi T1, T2, T3, T4, X, Y, Z;

#if defined(POLARSSL_SELF_TEST)
    add_count++;
#endif

    /*
     * Trivial cases: P == 0 or Q == 0 (case 1)
     */
    if( mpi_cmp_int( &P->Z, 0 ) == 0 )
        return( ecp_copy( R, Q ) );

    if( Q->Z.p != NULL && mpi_cmp_int( &Q->Z, 0 ) == 0 )
        return( ecp_copy( R, P ) );

    /*
     * Make sure Q coordinates are normalized
     */
    if( Q->Z.p != NULL && mpi_cmp_int( &Q->Z, 1 ) != 0 )
        return( POLARSSL_ERR_ECP_BAD_INPUT_DATA );

    mpi_init( &T1 ); mpi_init( &T2 ); mpi_init( &T3 ); mpi_init( &T4 );
    mpi_init( &X ); mpi_init( &Y ); mpi_init( &Z );

    MPI_CHK( mpi_mul_mpi( &T1,  &P->Z,  &P->Z ) );  MOD_MUL( T1 );
    MPI_CHK( mpi_mul_mpi( &T2,  &T1,    &P->Z ) );  MOD_MUL( T2 );
    MPI_CHK( mpi_mul_mpi( &T1,  &T1,    &Q->X ) );  MOD_MUL( T1 );
    MPI_CHK( mpi_mul_mpi( &T2,  &T2,    &Q->Y ) );  MOD_MUL( T2 );
    MPI_CHK( mpi_sub_mpi( &T1,  &T1,    &P->X ) );  MOD_SUB( T1 );
    MPI_CHK( mpi_sub_mpi( &T2,  &T2,    &P->Y ) );  MOD_SUB( T2 );

    /* Special cases (2) and (3) */
    if( mpi_cmp_int( &T1, 0 ) == 0 )
    {
        if( mpi_cmp_int( &T2, 0 ) == 0 )
        {
            ret = ecp_double_jac_patch( grp, R, P );
            goto cleanup;
        }
        else
        {
            ret = ecp_set_zero( R );
            goto cleanup;
        }
    }

    MPI_CHK( mpi_mul_mpi( &Z,   &P->Z,  &T1   ) );  MOD_MUL( Z  );
    MPI_CHK( mpi_mul_mpi( &T3,  &T1,    &T1   ) );  MOD_MUL( T3 );
    MPI_CHK( mpi_mul_mpi( &T4,  &T3,    &T1   ) );  MOD_MUL( T4 );
    MPI_CHK( mpi_mul_mpi( &T3,  &T3,    &P->X ) );  MOD_MUL( T3 );
    MPI_CHK( mpi_mul_int( &T1,  &T3,    2     ) );  MOD_ADD( T1 );
    MPI_CHK( mpi_mul_mpi( &X,   &T2,    &T2   ) );  MOD_MUL( X  );
    MPI_CHK( mpi_sub_mpi( &X,   &X,     &T1   ) );  MOD_SUB( X  );
    MPI_CHK( mpi_sub_mpi( &X,   &X,     &T4   ) );  MOD_SUB( X  );
    MPI_CHK( mpi_sub_mpi( &T3,  &T3,    &X    ) );  MOD_SUB( T3 );
    MPI_CHK( mpi_mul_mpi( &T3,  &T3,    &T2   ) );  MOD_MUL( T3 );
    MPI_CHK( mpi_mul_mpi( &T4,  &T4,    &P->Y ) );  MOD_MUL( T4 );
    MPI_CHK( mpi_sub_mpi( &Y,   &T3,    &T4   ) );  MOD_SUB( Y  );

    MPI_CHK( mpi_copy( &R->X, &X ) );
    MPI_CHK( mpi_copy( &R->Y, &Y ) );
    MPI_CHK( mpi_copy( &R->Z, &Z ) );

cleanup:

    mpi_free( &T1 ); mpi_free( &T2 ); mpi_free( &T3 ); mpi_free( &T4 );
    mpi_free( &X ); mpi_free( &Y ); mpi_free( &Z );

    return( ret );
}
/************************************************************
*
*3.sync functions that tls have but ssl not.
*
************************************************************/
/*
 * R = m * P with shortcuts for m == 1 and m == -1
 * NOT constant-time - ONLY for short Weierstrass!
 */
static int ecp_mul_shortcuts( ecp_group *grp,
                                      ecp_point *R,
                                      const mpi *m,
                                      const ecp_point *P )
{
    int ret;

    if( mpi_cmp_int( m, 1 ) == 0 )
    {
        MPI_CHK( ecp_copy( R, P ) );
    }
    else if( mpi_cmp_int( m, -1 ) == 0 )
    {
        MPI_CHK( ecp_copy( R, P ) );
        if( mpi_cmp_int( &R->Y, 0 ) != 0 )
            MPI_CHK( mpi_sub_mpi( &R->Y, &grp->P, &R->Y ) );
    }
    else
    {
        MPI_CHK( ecp_mul( grp, R, m, P, NULL, NULL ) );
    }

cleanup:
    return( ret );
}

/*
 * Linear combination
 * NOT constant-time
 */
static int ecp_muladd( ecp_group *grp, ecp_point *R,
             const mpi *m, const ecp_point *P,
             const mpi *n, const ecp_point *Q )
{
    int ret;
    ecp_point mP;

    if( ecp_get_type_patch( grp ) !=  1)   // 1 -> POLARSSL_ECP_TYPE_SHORT_WEIERSTRASS
        return( POLARSSL_ERR_ECP_FEATURE_UNAVAILABLE );

    ecp_point_init( &mP );

    MPI_CHK( ecp_mul_shortcuts( grp, &mP, m, P ) );
    MPI_CHK( ecp_mul_shortcuts( grp, R,   n, Q ) );

    MPI_CHK( ecp_add_mixed_patch( grp, R, &mP, R ) );
    MPI_CHK( ecp_normalize_jac_patch( grp, R ) );

cleanup:
    ecp_point_free( &mP );

    return( ret );
}
static int ecp_point_cmp( const ecp_point *P,
                           const ecp_point *Q )
{
    if( mpi_cmp_mpi( &P->X, &Q->X ) == 0 &&
        mpi_cmp_mpi( &P->Y, &Q->Y ) == 0 &&
        mpi_cmp_mpi( &P->Z, &Q->Z ) == 0 )
    {
        return( 0 );
    }

    return( POLARSSL_ERR_ECP_BAD_INPUT_DATA );
}

/****************************************************************************************************


                        Function of Initialization


****************************************************************************************************/
static void* my_calloc(size_t size)
{
    void *ptr = NULL;

    ptr = rtw_zmalloc(size);
    if(ptr)
        memset(ptr, 0, size);

    return ptr;
}
int rtw_platform_set_calloc_free( void * (*calloc_func)( size_t, size_t ),
                              void (*free_func)( void * ) )
{
    
	platform_set_malloc_free(my_calloc, free_func);
}
/****************************************************************************************************


                        Function of ECC Algorithm


****************************************************************************************************/
static const unsigned char secp224r1_a[]={ 
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE, 
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFE};

//***************************************************************************************************
// \brief           initialization of ecp curve with group id
//
// \param ecc       pointer of ecc curve structure
// \param group_id  group_id defined by spec 12.4
//
// \return         0  if successful,
//                 -1 if group_id is not supported
//***************************************************************************************************
int rtw_crypto_ecc_init(sae_ecc_crypto *ecc,unsigned char group_id)
{
	int ret = 0;
	ecp_group_init(ecc);
	switch (group_id){
		case 19:
		      ecp_use_known_dp( ecc, POLARSSL_ECP_DP_SECP256R1);
			  mpi_init(&ecc->A);
			  mpi_copy(&ecc->A,&ecc->P);
			  mpi_set_bit(&ecc->A,0,0);
			  mpi_set_bit(&ecc->A,1,0);
			  break;
		case 20:
	 		  ecp_use_known_dp( ecc, POLARSSL_ECP_DP_SECP384R1);
			  mpi_init(&ecc->A);
			  mpi_copy(&ecc->A,&ecc->P);
			  mpi_set_bit(&ecc->A,0,0);
			  mpi_set_bit(&ecc->A,1,0);
			  break;
		case 21:
			  ecp_use_known_dp( ecc, POLARSSL_ECP_DP_SECP521R1);
			  mpi_init(&ecc->A);
			  mpi_copy(&ecc->A,&ecc->P);
			  mpi_set_bit(&ecc->A,0,0);
			  mpi_set_bit(&ecc->A,1,0);
			  break;
		case 25:
			  ecp_use_known_dp( ecc, POLARSSL_ECP_DP_SECP192R1);
			  mpi_init(&ecc->A);
			  mpi_copy(&ecc->A,&ecc->P);
			  mpi_set_bit(&ecc->A,0,0);
			  mpi_set_bit(&ecc->A,1,0);
			  break;
		case 26:
			  ecp_use_known_dp( ecc, POLARSSL_ECP_DP_SECP224R1);
			  mpi_init(&ecc->A);
			  mpi_read_binary(&ecc->A,secp224r1_a,28);
			  break;
		default:
			  printf("\r\necc_init: no available ecc type: %d \n",group_id);
			  ret = -1;
			  break;
	}
	return ret;
}

//***************************************************************************************************
// \brief           free of ecp curve
//
// \param ecc       pointer of ecc curve structure
//
// \return          void
//
//***************************************************************************************************
void rtw_crypto_ecc_free(sae_ecc_crypto *ecc)
{
	mpi_free(&ecc->A);
	ecp_group_free(ecc);
}

//***************************************************************************************************
// \brief            get Parameter A of ECC
//
// \param ecc        pointer of ecc curve structure
// \param a          pointer of big number of a 
//
// \return  		 0 if successful
//                   -1 if fail
//
//***************************************************************************************************
int rtw_crypto_ecc_get_param_a(sae_ecc_crypto *ecc, sae_crypto_bignum *a)
{
	int ret = 0;
	if((ecc == NULL) || (a == NULL)){
		ret = -1;
		return ret;
	}

	MPI_CHK(mpi_copy(a,&ecc->A));

cleanup:	
	return ret;
}


//***************************************************************************************************
// \brief           get Parameter B of ECC
//
// \param ecc        pointer of ecc curve structure
// \param a          pointer of big number of a 
//
// \return  		0 if successful
//                  -1 if fail
//
//***************************************************************************************************
int rtw_crypto_ecc_get_param_b(sae_ecc_crypto *ecc, sae_crypto_bignum *b)
{
	int ret = 0;
	if((ecc == NULL) || (b == NULL)){
		ret = -1;
		return ret;
	}

	MPI_CHK(mpi_copy(b,&ecc->B));

cleanup:	
	return ret;
}

//***************************************************************************************************
// \brief           get Order of ECC
//
// \param ecc        pointer of ecc curve structure
// \param n          pointer of big number of a 
//
// \return  		0 if successful
//                  -1 if fail
//
//***************************************************************************************************
int rtw_crypto_ecc_get_param_order(sae_ecc_crypto *ecc, sae_crypto_bignum *n)
{
	int ret = 0;
	if((ecc == NULL) || (n == NULL)){
		ret = -1;
		return ret;
	}

	MPI_CHK(mpi_copy(n,&ecc->N));

cleanup:	
	return ret;
}


//***************************************************************************************************
// \brief           get Parameter B of ECC
//
// \param ecc        pointer of ecc curve structure
// \param a          pointer of big number of a 
//
// \return  		0 if successful
//                  -1 if fail
//
//***************************************************************************************************
int rtw_crypto_ecc_get_param_prime(sae_ecc_crypto *ecc, sae_crypto_bignum *prime)
{
	int ret = 0;
	if((ecc == NULL) || (prime == NULL)){
		ret = -1;
		return ret;
	}
	
	MPI_CHK(mpi_copy(prime,&ecc->P));

cleanup:	
	return ret;
}


/*********************************************************************************************
// \brief:     import point from bignum

// \param ecc: pointer of ecc
// \param x:   input point x
// \param y:   input point y 
// \param p:   import point
//          
return:    0 if successful
		   -1 if failed
*********************************************************************************************/
int rtw_crypto_ecc_point_read_bignum(sae_ecc_crypto *ecc,sae_crypto_bignum *x,sae_crypto_bignum *y,sae_ecc_point *p)
{
	int ret = 0;
	unsigned char *buf = NULL;
	unsigned int buf_len;
	unsigned int prime_len;

	if((ecc == NULL) || (x == NULL) || (y == NULL) || (p == NULL)){
		ret = -1;
		goto cleanup;
	}

    if( ecc->P.n == 0 )
    {
        prime_len = 0;
    }
    else
    {
    	prime_len = mpi_size(&ecc->P);
    }
	
	buf_len = 2*prime_len + 1;

	buf = rtw_zmalloc(buf_len);

	if(buf == NULL){
		ret = -1;
		goto cleanup;
	}

	buf[0] = 0x04;
	
	if(rtw_crypto_bignum_write_binary(x,buf + 1,prime_len) < 0){
		ret = -1;
		goto cleanup;
	}

	if(rtw_crypto_bignum_write_binary(y,buf + 1 + prime_len,prime_len) < 0){
		ret = -1;
		goto cleanup;
	}

	ret = ecp_point_read_binary(ecc,p,buf,buf_len);

		
cleanup:
	if(buf)
		rtw_mfree(buf,buf_len);
	return ret;
	
}

/*********************************************************************************************
brief:     export point to bignum 

Parameter: ecc: pointer of ecc
           x:  output point x
           y:  output point y
           p:  export point of ecc
           
return:    0 if successful
		   -1 if failed
*********************************************************************************************/
int rtw_crypto_ecc_point_write_bignum(sae_ecc_crypto *ecc,sae_crypto_bignum *x,sae_crypto_bignum *y,sae_ecc_point *p)
{
	int ret = 0;
	unsigned char *buf = NULL;
	unsigned int buf_len;
	unsigned int prime_len;
	unsigned int out_len = 0;


	if((ecc == NULL) || (x == NULL) || (y == NULL) || (p == NULL)){
		ret = -1;
		goto cleanup;
	}

    if( ecc->P.n == 0 )
    {
        prime_len = 0;
    }
    else
    {
    	prime_len = mpi_size(&ecc->P);
    }

	buf_len = 2*prime_len + 1;

	buf = rtw_zmalloc(buf_len);

	if(buf == NULL){
		ret = -1;
		goto cleanup;
	}

	if(ecp_point_write_binary(ecc,p,POLARSSL_ECP_PF_UNCOMPRESSED,&out_len,buf,buf_len) <0 ){
		ret = -1;
		goto cleanup;
	}

	if(rtw_crypto_bignum_read_binary(x,buf + 1, prime_len) < 0){
		ret = -1;
		goto cleanup;
	}
	
	
	if(rtw_crypto_bignum_read_binary(y,buf + 1 + prime_len, prime_len) < 0){
		ret = -1;
		goto cleanup;
	}
	
		
cleanup:
	if(buf)
		rtw_mfree(buf,buf_len);
	return ret;
	
}


//***************************************************************************************************
// \brief			Initialize one ecc point
//
// \param point		pointer to ecc point
//
// \return			void
//					
//***************************************************************************************************
void rtw_crypto_ecc_point_init(sae_ecc_point *point)
{
	ecp_point_init(point);
}

//***************************************************************************************************
// \brief			Free one ecc point
//
// \param point		pointer to ecc point
//
// \return			void
//					
//***************************************************************************************************
void rtw_crypto_ecc_point_free(sae_ecc_point *point)
{
	ecp_point_free(point);
}

//***************************************************************************************************
// \brief			check the ecc point is the infinity point
//
// \param point		pointer to ecc point
//
// \return			0  none-infinity 
//					1  infinity				
//***************************************************************************************************
int rtw_crypto_ecc_point_is_at_infinity(sae_ecc_point *point)
{
	return ecp_is_zero(point);
}

//***************************************************************************************************
// \brief			R = m * P 
//
// \param ecc		pointer of ecc curve structure
// \param R			pointer to the result ecc point
// \param m			pointer to a bignum
// \param P         pointer to the source 
// \return			0  success
//					-1 fail
//***************************************************************************************************
int rtw_crypto_ecc_point_mul_bignum(sae_ecc_crypto *ecc,sae_ecc_point *R,sae_crypto_bignum *m,sae_ecc_point *P)
{
	int ret = 0;	
	MPI_CHK( ecp_mul( ecc, R, m, P, NULL, NULL ));
cleanup:
	if(ret < 0)
		ret = -1;
	return ret;
}

//***************************************************************************************************
// \brief			justify if the ecc point is on the curve
//
// \param ecc		pointer of ecc curve structure
// \param P         pointer to the ecc point 

// \return			0  yes
//					-1 no 
//***************************************************************************************************
int rtw_crypto_ecc_point_is_on_curve(sae_ecc_crypto *ecc,sae_ecc_point *P)
{
	int ret = 0;	

	MPI_CHK(ecp_check_pubkey(ecc,P));

cleanup:	
	if(ret < 0)
		ret = -1;
	return ret;
}


//***************************************************************************************************
// \brief			X = A + B 
//
// \param ecc		pointer of ecc curve structure
// \param X			pointer of destination point
// \param A			pointer of left hand point
// \param B         pointer of right hand point
//
// \return			0  success
//					-1 fail
//***************************************************************************************************
int rtw_crypto_ecc_point_add_point(sae_ecc_crypto *ecc,sae_ecc_point *X,sae_ecc_point *A,sae_ecc_point *B)
{
	int ret = 0;
	mpi one;

	mpi_init(&one);
	
    MPI_CHK(mpi_lset(&one,1));
    MPI_CHK(ecp_muladd(ecc,X,&one,A,&one,B));

cleanup:
	if(ret < 0)
		ret = -1;
	mpi_free(&one);
	return ret;
}

//***************************************************************************************************
// \brief			compare two ecc points
//
// \param ecc		pointer of ecc curve structure
// \param P1		pointer of left hand point
// \param P2        pointer of right hand point
//
// \return			0  P1 = P2
//					<0 P1 != P2
//***************************************************************************************************
int rtw_crypto_ecc_point_cmp(sae_ecc_point *P1,sae_ecc_point *P2)
{
	return ecp_point_cmp(P1,P2);
}


/****************************************************************************************************


                        Function of Big number Operation and computation
                        

****************************************************************************************************/


//***************************************************************************************************
// \brief			Initialize one Big number
//                  This just makes it ready to be set or freed, but does not define a value for the MPI
//
// \param X		    pointer of one big number to be initialized
//
// \return			void					
//
//***************************************************************************************************
void rtw_crypto_bignum_init(sae_crypto_bignum *X)
{
	mpi_init(X);
}

void rtw_crypto_bignum_init_set(sae_crypto_bignum *X, const u8 *buf, size_t len)
{
	mpi_init(X);
	mpi_read_binary(X, buf, len);
}

void rtw_crypto_bignum_init_int(sae_crypto_bignum *X, int val)
{
	mpi_init(X);
	mpi_lset(X,val);
}

//***************************************************************************************************
// \brief			unallocate one big number
//
// \param X		    pointer of big number to be unallocated
//
// \return			void					
//
//***************************************************************************************************
void rtw_crypto_bignum_free(sae_crypto_bignum *X)
{
	mpi_free(X);
}

//***************************************************************************************************
// \brief			Copy the contents of Y into X
//
// \param X		    pointer of destination big number
// \param Y			pointer of source big number
//
// \return			0 if successful
//					-1 if failed
//
//***************************************************************************************************
int rtw_crypto_bignum_copy(sae_crypto_bignum *X,sae_crypto_bignum *Y)
{
	int ret = 0;
	MPI_CHK(mpi_copy(X,Y));
	
cleanup:
	if((ret) < 0)
		ret = -1;
	return ret;
}


//***************************************************************************************************
// \brief			Return the number of bits up to and including the most significant '1' bit'
//
// \param X		    pointer of big number to use
//
// \return			length of bit					
//
//***************************************************************************************************
size_t rtw_crypto_bignum_bitlen(sae_crypto_bignum *X)
{
    size_t ret;
    
    if( X->n == 0 )
    {
        ret = 0;
    }
    else
    {
    	ret = mpi_msb(X);
    }

    return ret;
}


//***************************************************************************************************
// \brief			Get a specific bit from X
//
// \param X		    pointer of big number to use
// \param pos		Zero-based index of the bit in X
//
// \return			either 0 or 1					
//
//***************************************************************************************************
size_t rtw_crypto_bignum_get_bit(sae_crypto_bignum *X,size_t pos)
{
	return mpi_get_bit(X,pos);
}


//***************************************************************************************************
// \brief			return the total size in bytes
//
// \param X		    pointer of big number to use
//
// \return			total size of big number in bytes				
//
//***************************************************************************************************
size_t rtw_crypto_bignum_size(sae_crypto_bignum *X)
{
    size_t ret;
    
    if( X->n == 0 )
    {
        ret = 0;
    }
    else
    {
    	ret = mpi_size(X);
    }

    return ret;
}


//***************************************************************************************************
// \brief			Import X from unsigned binary data, big endian
//
// \param X		    pointer of destination big number
// \param buf		pointer of input buffer
// \param buf_len   input buffer size
//
// \return			0 if successful				
//					-1 if failed
//
//***************************************************************************************************
int rtw_crypto_bignum_read_binary(sae_crypto_bignum *X,const unsigned char *buf, size_t buf_len)
{
	int ret = 0;
	MPI_CHK(mpi_read_binary(X,buf,buf_len));
		
cleanup:		
	if((ret)<0)
		ret = -1;

	return ret;
}


//***************************************************************************************************
// \brief			 Export X into unsigned binary data, big endian.
//					 Always fills the whole buffer, which will start with zeros if the number is smaller.
//
// \param X		    pointer of source big number
// \param buf		pointer of output buffer
// \param buf_len   output buffer size
//
// \return			0 if successful				
//					-1 if failed
//
//***************************************************************************************************
int rtw_crypto_bignum_write_binary(sae_crypto_bignum *X,unsigned char *buf, size_t buf_len)
{
	int ret = 0;
	MPI_CHK(mpi_write_binary(X,buf,buf_len));
		
cleanup:		
	if((ret)<0)
		ret = -1;

	return ret;
}

//***************************************************************************************************
// \brief			 Right-shift: X >>= count
//
// \param X		    pointer of big number to shift
// \param count		amount to shift
//
// \return			0 if successful				
//					-1 if failed
//
//***************************************************************************************************
int rtw_crypto_bignum_shift_r(sae_crypto_bignum *X,size_t count)
{
	int ret = 0;
	MPI_CHK(mpi_shift_r(X,count));
		
cleanup:		
	if((ret)<0)
		ret = -1;

	return ret;
}

//***************************************************************************************************
// \brief			Compare signed values
//
// \param X		    pointer of left hand big number
// \param Y		    pointer of right hand big number
//
// \return			1 if X is greater than Y				
//					-1 if X is lesser than Y
//					0 if X is equal to Y
//
//***************************************************************************************************
int rtw_crypto_bignum_cmp_bignum(sae_crypto_bignum *X,sae_crypto_bignum *Y)
{
	return mpi_cmp_mpi(X,Y);
}

//***************************************************************************************************
// \brief			Compare signed values
//
// \param X		    pointer of left hand big number
// \param z		    The integer value to compare to
//
// \return			1 if X is greater than z				
//					-1 if X is lesser than z
//					0 if X is equal to z
//
//***************************************************************************************************
int rtw_crypto_bignum_cmp_int(sae_crypto_bignum *X,int z)
{
	return mpi_cmp_int(X,z);
}

//***************************************************************************************************
// \brief			Signed addition:X = A + B
//
// \param X		    pointer of destination big number
// \param A		    pointer of left hand big number
// \param B			pointer of right hand big number
//
// \return			0 if successful					
//					-1 if failed
//
//***************************************************************************************************
int rtw_crypto_bignum_add_bignum(sae_crypto_bignum *X,sae_crypto_bignum *A,sae_crypto_bignum *B)
{
	int ret = 0;
	MPI_CHK(mpi_add_mpi(X,A,B));
		
cleanup:		
	if((ret)<0)
		ret = -1;

	return ret;
}


//***************************************************************************************************
// \brief			Signed addition: X = A + b
//
// \param X		    pointer of destination big number
// \param A		    pointer of left hand big number
// \param b			The integer value to add
//
// \return			0 if successful					
//					-1 if failed
//
//***************************************************************************************************
int rtw_crypto_bignum_add_int(sae_crypto_bignum *X,sae_crypto_bignum *A,int b)
{
	int ret = 0;
	MPI_CHK(mpi_add_int(X,A,b));
		
cleanup:		
	if((ret)<0)
		ret = -1;

	return ret;
}

//***************************************************************************************************
// \brief			Signed addition: X = A - B
//
// \param X		    pointer of destination big number
// \param A		    pointer of left hand big number
// \param B			pointer of right hand big number
//
// \return			0 if successful					
//					-1 if failed
//
//***************************************************************************************************
int rtw_crypto_bignum_sub_bignum(sae_crypto_bignum *X,sae_crypto_bignum *A,sae_crypto_bignum *B)
{
	int ret = 0;
	MPI_CHK(mpi_sub_mpi(X,A,B));
		
cleanup:		
	if((ret)<0)
		ret = -1;

	return ret;
}


//***************************************************************************************************
// \brief			Signed addition: X = A - b
//
// \param X		    point of destination big number
// \param A		    point of left hand big number
// \param b			The integer value to subtract
//
// \return			0 if successful					
//					-1 if failed
//
//***************************************************************************************************
int rtw_crypto_bignum_sub_int(sae_crypto_bignum *X,sae_crypto_bignum *A,int b)
{
	int ret = 0;
	MPI_CHK(mpi_sub_int(X,A,b));
		
cleanup:		
	if((ret)<0)
		ret = -1;

	return ret;
}

//***************************************************************************************************
// \brief			Division by big number: A = Q * B + R
//
// \param Q		    pointer of destination big number for the quotient
// \param R		    pointer of destination big number for the rest value
// \param A			pointer of left hand big number
// \param B			pointer of right hand big number
//
// \return			0 if successful					
//					-1 if failed
// 
// \note 			Either Q or R can be NULL.
//***************************************************************************************************
int rtw_crypto_bignum_div_bignum(sae_crypto_bignum *Q,sae_crypto_bignum *R,sae_crypto_bignum *A,sae_crypto_bignum *B)
{
	int ret = 0;
	MPI_CHK(mpi_div_mpi(Q,R,A,B));
		
cleanup:		
	if((ret)<0)
		ret = -1;

	return ret;
}


//***************************************************************************************************
// \brief			X = A mod N
//
// \param X		    pointer of destination big number
// \param A		    pointer of left hand big number
// \param N			pointer of modular big number
//
// \return			0 if successful					
//					-1 if failed
//
//***************************************************************************************************
int rtw_crypto_bignum_mod_bignum(sae_crypto_bignum *X,sae_crypto_bignum *A,sae_crypto_bignum *N)
{
	int ret = 0;
	MPI_CHK(mpi_mod_mpi(X,A,N));
		
cleanup:		
	if((ret)<0)
		ret = -1;

	return ret;
}

//***************************************************************************************************
// \brief			X = (A + B) mod N
//
// \param X		    pointer of destination big number
// \param A		    pointer of left hand big number
// \param B 		pointer of right hand big number
// \param N			pointer of modular big number
//
// \return			0 if successful					
//					-1 if failed
//
//***************************************************************************************************
int rtw_crypto_bignum_add_mod(sae_crypto_bignum *X,sae_crypto_bignum *A,sae_crypto_bignum *B,sae_crypto_bignum *N)
{
	int ret = 0;
	MPI_CHK(mpi_add_mpi(X,A,B));
	MPI_CHK(mpi_mod_mpi(X,X,N));
		
cleanup:		
	if((ret)<0)
		ret = -1;

	return ret;
}

//***************************************************************************************************
// \brief			X = (A * B) mod N
//
// \param X		    pointer of destination big number
// \param A		    pointer of left hand big number
// \param B 		pointer of right hand big number
// \param N			pointer of modular big number
//
// \return			0 if successful					
//					-1 if failed
//
//***************************************************************************************************
int rtw_crypto_bignum_mul_mod(sae_crypto_bignum *X,sae_crypto_bignum *A,sae_crypto_bignum *B,sae_crypto_bignum *N)
{
	int ret = 0;
	MPI_CHK(mpi_mul_mpi(X,A,B));
	MPI_CHK(mpi_mod_mpi(X,X,N));
		
cleanup:		
	if((ret)<0)
		ret = -1;

	return ret;
}

//***************************************************************************************************
// \brief			X = (A ^ B) mod N
//
// \param X		    pointer of destination big number
// \param A		    pointer of left hand big number
// \param B 		pointer of right hand big number
// \param N			pointer of modular big number
//
// \return			0 if successful					
//					-1 if failed
//
//***************************************************************************************************
int rtw_crypto_bignum_exp_mod(sae_crypto_bignum *X,sae_crypto_bignum *A,sae_crypto_bignum *B,sae_crypto_bignum *N)
{
	int ret = 0;
	MPI_CHK(mpi_exp_mod(X,A,B,N,NULL));
		
cleanup:		
	if((ret)<0)
		ret = -1;

	return ret;
}


//***************************************************************************************************
// \brief		assign Y ==> X
//
// \param X     pointer to bignum X
// \param Y		pointer to bignum Y
// \param inv   assign or not
//
// \return		0 if successful
//				-1 if failed				
//***************************************************************************************************
int rtw_crypto_bignum_assign(sae_crypto_bignum *X, sae_crypto_bignum *Y,unsigned char inv)
{
	int ret = 0;

	MPI_CHK(mpi_safe_cond_assign(X,Y,inv));
		
cleanup:
	if(ret < 0)
		ret = -1;
	return ret;
}

//***************************************************************************************************
// \brief		X = A^-1 mod N
//
// \param X     pointer to bignum X
// \param Y		pointer to bignum Y
// \param inv   assign or not
//
// \return		0 if successful
//				-1 if failed				
//***************************************************************************************************
int rtw_crypto_bignum_inverse(sae_crypto_bignum *X, sae_crypto_bignum *A,sae_crypto_bignum *N)
{
	int ret = 0;

	MPI_CHK(mpi_inv_mod(X,A,N));
		
cleanup:
	if(ret < 0)
		ret = -1;
	return ret;
}

int crypto_ec_point_from_bin(unsigned int prime_len, u8 *val, sae_ecc_point *point)
{
	int ret = 0;

	if (rtw_crypto_bignum_read_binary(&point->X, val, prime_len) < 0){
		ret=-1;
		goto cleanup;
	}

	if (rtw_crypto_bignum_read_binary(&point->Y, val + prime_len, prime_len) < 0){
		ret=-1;
		goto cleanup;
	}
	rtw_crypto_bignum_init_int(&point->Z, 1);

cleanup:
	return ret;
}

int crypto_ec_point_to_bin(unsigned int prime_len, sae_ecc_point *point, u8 *x, u8 *y)
{
	if (x) {
		if (rtw_crypto_bignum_write_binary(&point->X, x, prime_len) < 0)
			return -1;
	}

	if (y) {
		if (rtw_crypto_bignum_write_binary(&point->Y, y, prime_len) < 0)
			return -1;
	}

	return 0;
}

#endif
