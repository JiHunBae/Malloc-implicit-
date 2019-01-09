/*
 * mm-explicit.c - an empty malloc package
 *
 * NOTE TO STUDENTS: Replace this header comment with your own header
 * comment that gives a high level description of your solution.
 *
 * @id : 201502061
 * @name : 배지훈
 */
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "mm.h"
#include "memlib.h"

 /* If you want debugging output, use the following macro.  When you hand
  * in, remove the #define DEBUG line. */
#define DEBUG
#ifdef DEBUG
# define dbg_printf(...) printf(__VA_ARGS__)
#else
# define dbg_printf(...)
#endif


  /* do not change the following! */
#ifdef DRIVER
/* create aliases for driver tests */
#define malloc mm_malloc
#define free mm_free
#define realloc mm_realloc
#define calloc mm_calloc
#endif /* def DRIVER */

/* single word (4) or double word (8) alignment */
#define ALIGNMENT 8

#define ALIGN(p) (((size_t)(p) + (ALIGNMENT-1)) & ~0x7)

#define HDRSIZE 4
#define FTRSIZE 4
#define WSIZE 4
#define DSIZE 8
#define CHUNKSIZE (1 << 12)
#define OVERHEAD 8

#define MAX(x,y) ((x) > (y) ? (x) : (y))
#define MIN(x,y) ((x) < (y) ? (x) : (y))

#define PACK(size, alloc)  ((size) | (alloc))

#define GET(p) (*(unsigned int*) (p))
#define PUT(p, val) (*(unsigned int*) (p) = (val)) 
#define GET8(p) (*(unsigned long *) (p))
#define PUT8(p, val) (*(unsigned long*) (p) = (unsigned long) (val))
#define GET_SIZE(p) (GET(p) & ~0x7)
#define GET_ALLOC(p) (GET(p) & 0x1)

#define HDRP(bp) ((char *)(bp) - WSIZE)
#define FTRP(bp) ((char *)(bp) + GET_SIZE(HDRP(bp)) - DSIZE)
#define NEXT_BLKP(bp) ((char *)(bp) + GET_SIZE(HDRP(bp)))
#define PREV_BLKP(bp) ((char *)(bp) - GET_SIZE((char *)(bp) -  DSIZE))

#define NEXT_FREEP(bp) ((char *)(bp))
#define PREV_FREEP(bp) ((char *)(bp) + WSIZE)

#define NEXT_FREE_BLKP(bp) ((char *)GET((char *)(bp)))
#define PREV_FREE_BLKP(bp) ((char *)GET((char *)(bp)+DSIZE))

#define SIZE_T_SIZE (ALIGN(sizeof(size_t)))
#define SIZE_PTR(p) ((size_t*)(((char *)(p)) - SIZE_T_SIZE))
/* rounds up to the nearest multiple of ALIGNMENT */

static void *delete_Free_Block(void *bp);
static void *insert_Free_Block(void *bp);
static void *extended_heap(size_t words);
static void *place(void *bp, size_t size);
static void *find_fit(size_t asize);
static void *coalesce(void *bp);
static char *h_ptr = 0;
static char *heap_start = 0;
static void *epilogue = 0;
/*
 * Initialize: return -1 on error, 0 on success.
 */
int mm_init(void) {//
	if ((h_ptr = mem_sbrk(DSIZE + (4 * HDRSIZE))) == NULL) // 24바이트 메모리 공간 확보
		return -1;


	heap_start = h_ptr; // 반환e 받은 메모리 주소 시작점을 heap_start에 저장
	PUT8(h_ptr, NULL); // NEXT 
	PUT(h_ptr + WSIZE, NULL); 
	PUT(h_ptr + DSIZE, 0); // 0  

	PUT(h_ptr + DSIZE + HDRSIZE, PACK(OVERHEAD, 1)); // HDR 
	PUT(h_ptr + DSIZE + HDRSIZE + FTRSIZE, PACK(OVERHEAD, 1)); // FTR 
	//프롤로그
	PUT(h_ptr + DSIZE + 2 * HDRSIZE + FTRSIZE, PACK(0, 1)); // 

	// 에필로그
	h_ptr += DSIZE + DSIZE;

	epilogue = h_ptr + HDRSIZE;
	// 힙 확장
	if (extended_heap(CHUNKSIZE / WSIZE) == NULL)
		return -1;

	return 0;
}

void *extended_heap(size_t words) {///
	unsigned char *bp;
	unsigned size;

	size = (words % 2) ? (words + 1) * WSIZE : words * WSIZE; // size값 조정

	if ((long)(bp = mem_sbrk(size)) < 0) // size값 만큼 힙 확장
		return NULL;

	epilogue = bp + size - HDRSIZE; // 에필로그 부분
	PUT(HDRP(bp), size);
	PUT(FTRP(bp), PACK(size, 0));


	PUT(epilogue, PACK(0, 1));

	return coalesce(bp);
}

/*
 * malloc
 */
static int count = 0;
void *malloc(size_t size) {
	// implicit과 동일
	char *bp;
	size_t asize;
	size_t extendsize;

	printf("%d\n", ++count);
	if (size <= 0)
		return NULL;

	if (size <= DSIZE)
		asize = 2 * DSIZE;
	else
		asize = DSIZE * ((size + (DSIZE)+(DSIZE - 1)) / DSIZE);

	if ((bp = find_fit(asize)) != NULL) {
		place(bp, asize);
		return bp;
	}

	extendsize = MAX(asize, CHUNKSIZE);

	if ((bp = extended_heap(extendsize / WSIZE)) == NULL)
		return NULL;

	place(bp, asize);
	return bp;
}

static void *delete_Free_Block(void *bp) {
	unsigned char *next_Free = GET(bp);// bp의 원래 NEXT FREE BLOCK 주소
	unsigned char *prev_Free = GET(bp+4); // bp의 원래 PREV FREE BLOCK 주소
	if (next_Free != NULL) { // bp가 Free 블럭 링크의 리프노드가 아닌 경우
		PUT(NEXT_FREEP(prev_Free), next_Free); // 원래 PREV_FREE_BLOCK의 NEXT를 bp의 원래 NEXT FREE BLOCK으로 변경
		PUT(PREV_FREEP(next_Free), prev_Free); // 원래 NEXT FREE BLOCK의 PREV를 bp의 원래 PREV FREE BLOCK으로 변경
		
		// 기존의 NEXT와 PREV에 0을 넣어준다. (꼭 0을 해줄 필요는 없지만, 그냥 비워주었다)
		PUT(NEXT_FREEP(bp), 0);
		PUT(PREV_FREEP(bp), 0);
	
	}
	else if (next_Free == NULL) { // bp가 Free블럭 링크의 리프노드인 경우
		PUT(NEXT_FREEP(prev_Free), NULL); // 원래 PREV_FREE_BLOCK의 NEXT를 NULL로 설정
	}//
}

static void *insert_Free_Block(void *bp) {
	unsigned char *next_Free = NEXT_FREE_BLKP(heap_start); // heap_start의 NEXT_FREE_BLOCK 주소
	if (next_Free != NULL) { // heap_start의 NEXT_FREE_BLOCK이 NULL이 아닌 경우
		PUT(NEXT_FREEP(bp), next_Free);  // bp(NEXT)의값에 heap_start의 NEXT_FREE_BLOCK주소값을 넣어줌
		PUT(PREV_FREEP(bp), heap_start); // bp+WSIZE(PREV)의 값에 heap_start의 PREV_FREE_BLOCK주소값을 넣어줌
		PUT(NEXT_FREEP(heap_start), bp); // heap_start의 주소값에 NEXT값을 넣어줌
		PUT(PREV_FREEP(next_Free), bp); // NEXT_FREE_BLOCK의 PREV FREE BLOCK의 주소값을 담는 칸에 현재 블럭 주소값을 넣어줌
	}
	else if (next_Free == NULL) {// heap_start의 NEXT_FREE_BLOCK이 NULL인 경우
		PUT(NEXT_FREEP(heap_start), bp); // FREE BLOCK 에 bp추가
		PUT(PREV_FREEP(bp), heap_start); // bp의 PREV FREE BLOCK에 heap_start추가
		PUT(NEXT_FREEP(bp), NULL); // bp의 NEXT에 NULL 넣어줌
	}
}

static void *place(void *bp, size_t asize) {
	size_t csize = GET_SIZE(HDRP(bp));

	if ((csize - asize) >= OVERHEAD + 2 * DSIZE) {
		PUT(HDRP(bp), PACK(asize, 1));
		PUT(FTRP(bp), PACK(asize, 1));
		// HDR과 FTR에 size값과 alloc임을 나타내게함
		delete_Free_Block(bp);
		bp = NEXT_BLKP(bp);
		PUT(HDRP(bp), PACK(csize - asize, 0));
		PUT(FTRP(bp), PACK(csize - asize, 0));
		insert_Free_Block(bp);
		// 그 다음 뒤에 남은 블록들을 남은 할당하고 남은 크기값과 free임을 나타내게함.
	}
	else {
		PUT(HDRP(bp), PACK(csize, 1));
		PUT(FTRP(bp), PACK(csize, 1));
		delete_Free_Block(bp);
		/*
		 * 최소 크기인 24를 넘기지 못하는 블럭들을 묶어서 같이 alloc해준다
		 * 16바이트로는 HDR,FTR,NEXT,PREV밖에 만들지 못하기 때문이다.
		 */
	}
}
//
static void *find_fit(size_t asize) {
	void *bp = NEXT_FREE_BLKP(heap_start);
	// Free블럭 리스트중에서 사이즈값 맞는 것 나오면 주소값 반환 실패시 NULL반환
	for (;((bp != NULL) && (mem_heap_lo() < bp) && (bp< mem_heap_hi())); bp = NEXT_FREE_BLKP(bp)) {
		if ((asize <= GET_SIZE(HDRP(bp)))) {
			return bp;
		}
	}
	//
	return NULL;
}
/*
 * free
 */
void free(void *ptr) {
	// 메모리 할당을 풀어주는 함수
	if (!ptr) return;

	size_t size = GET_SIZE(HDRP(ptr));

	PUT(HDRP(ptr), PACK(size, 0));
	PUT(FTRP(ptr), PACK(size, 0));
	coalesce(ptr);
}

static void *coalesce(void *bp) {
	char prev_alloc = GET_ALLOC(bp - DSIZE);
	// 메모리에서의 이전 블록이 ALLOC인지 확인
	unsigned int size = GET_SIZE(HDRP(bp));
	char next_alloc = GET_ALLOC(HDRP(bp) + size);
	// 메모리에서의 다음 블록이 ALLOC인지 확인

	if (prev_alloc && next_alloc) {
		// 이전 블록과 다음 블록이 모두 alloc인 경우
		insert_Free_Block(bp);
	}
	else if (!prev_alloc && next_alloc) {
		// 이전 블록이 free이고 다음 블록이 alloc인 경우
		size += GET_SIZE(HDRP(PREV_BLKP(bp)));
		PUT(HDRP(bp) + size, PACK(size, 0));
		PUT(HDRP(PREV_BLKP(bp)), PACK(size, 0));
	}
	else if (prev_alloc && !next_alloc) {
		// 이전 블록이 alloc이고 다음 블록이 free인 경우
		size += GET_SIZE(HDRP(NEXT_BLKP(bp)));
		delete_Free_Block(NEXT_BLKP(bp));
		PUT(HDRP(bp), PACK(size, 0));
		PUT(FTRP(NEXT_BLKP(bp)), PACK(size, 0));
		insert_Free_Block(bp);
	}
	else {
		// 이전 블록과 다음 블록이 모두 free인 경우
		size += GET_SIZE(HDRP(PREV_BLKP(bp))) + GET_SIZE(HDRP(NEXT_BLKP(bp)));
		delete_Free_Block(NEXT_BLKP(bp));
		PUT(HDRP(PREV_BLKP(bp)), PACK(size, 0));
		PUT(FTRP(NEXT_BLKP(bp)), PACK(size, 0));
		insert_Free_Block(PREV_BLKP(bp));		
	}
}
/*
 * realloc - you may want to look at mm-naive.c
 */
void *realloc(void *oldptr, size_t size) {
	// implicit과 동일
	size_t oldsize;
	void *newptr;

	if (size == 0) {
		free(oldptr);
		return 0;
	}

	if (oldptr == NULL) {
		return malloc(size);
	}
	newptr = malloc(size);

	if (!newptr) {
		return 0;
	}

	oldsize = *SIZE_PTR(oldptr);

	if (size < oldsize)
		oldsize = size;

	memcpy(newptr, oldptr, oldsize);

	free(oldptr);

	return newptr;
}

/*
 * calloc - you may want to look at mm-naive.c
 * This function is not tested by mdriver, but it is
 * needed to run the traces.
 */
void *calloc(size_t nmemb, size_t size) {
	//implicit과 동일
	size_t bytes = nmemb * size;
	void *newptr;

	newptr = malloc(bytes);
	memset(newptr, 0, bytes);
	return newptr;
}


/*
 * Return whether the pointer is in the heap.
 * May be useful for debugging.
 */
static int in_heap(const void *p) {
	return p < mem_heap_hi() && p >= mem_heap_lo();
}

/*
 * Return whether the pointer is aligned.
 * May be useful for debugging.
 */
static int aligned(const void *p) {
	return (size_t)ALIGN(p) == (size_t)p;
}

/*
 * mm_checkheap
 */
void mm_checkheap(int verbose) {
}
