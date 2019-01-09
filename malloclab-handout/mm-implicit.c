/*
 * mm-implicit.c - an empty malloc package
 *
 * NOTE TO STUDENTS: Replace this header comment with your own header
 * comment that gives a high level description of your solution.
 *
 * @id :
 * @name :
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

/* rounds up to the nearest multiple of ALIGNMENT */
#define ALIGN(p) (((size_t)(p) + (ALIGNMENT-1)) & ~0x7)

#define WSIZE 4 // 싱글워드 사이즈
#define DSIZE 8 // 더블워드 사이즈
#define CHUNKSIZE (1 << 12) // 4096(상수)
#define OVERHEAD 8 // 8바이트를 의미
#define MAX(x,y) ((x) > (y) ? (x) : (y)) // x,y중 큰 값 반환
#define PACK(size, alloc) ((size)|(alloc)) // OR비트 연산을 통한 값 반환
#define SIZE_T_SIZE (ALIGN(sizeof(size_t))) // 이 개발환경에서는 8을 의미
#define SIZE_PTR(p) ((size_t*)(((char*)(p))-SIZE_T_SIZE))
#define GET(p) (*(unsigned int*)(p)) // 해당 주소의 값을 반환
#define PUT(p, val) (*(unsigned int*)(p) = (val)) // 해당 주소에 val값을 저장
#define GET_SIZE(p) (GET(p) & ~0x7) // size값 반환
#define GET_ALLOC(p) (GET(p)&0x1) // alloc , free인지 반환
#define HDRP(bp) ((char*)(bp) - WSIZE) // bp의 HDR
#define FTRP(bp) ((char*)(bp) + GET_SIZE(HDRP(bp))-DSIZE) // bp의 FTR
#define NEXT_BLKP(bp) ((char*)(bp) + GET_SIZE((char*)(bp)-WSIZE)) // bp의 다음 블록
#define PREV_BLKP(bp) ((char*)(bp) - GET_SIZE((char*)(bp)-DSIZE)) // bp의 이전 블록
static void *coalesce(void *bp); // Free 블록 합병함수
static void place(void *bp, size_t asize); // 메모리 공간을 alloc해주는 함수
static void *extended_heap(size_t words);// 힙 확장함수
static void *find_fit(size_t asize);// Free블록이면서 size가 맞는 블록을 찾는 함수
static char *heap_listp = 0; // 힙의 시작점
static char *find_point; // 검색 포인터
/*
 * Initialize: return -1 on error, 0 on success.
 */
int mm_init(void) {
	/* 최초에  빈 힙을 만드는 함수 */

	if((heap_listp = mem_sbrk(4 * WSIZE)) == NULL)
		return -1;

	PUT(heap_listp, 0); // 힙의 첫 번째 주소에 0이라는 값을 넣어줌
	PUT(heap_listp + WSIZE, PACK(OVERHEAD, 1));// hdr
	PUT(heap_listp + DSIZE, PACK(OVERHEAD, 1));// ftr
	// 위의 두 문장에 해당하는 put함수는 프롤로그 부분 구현
	PUT(heap_listp + WSIZE + DSIZE, PACK(0, 1));
	// hdr , 위의 put함수는 에필로그 부분 구현
	heap_listp += DSIZE;
	// heap_listp를 heap의 프롤로그 다음으로 넘겨준다.

	find_point = heap_listp;

	if(extended_heap(CHUNKSIZE/WSIZE) == NULL)
		return -1;

	return 0;
}//

static void *extended_heap(size_t words) {
	/* heap을 늘리는 함수 */

	char *bp; // 주소값 받기 위한 변수
	size_t size; // heap을 얼마나 늘릴것인지 그 값을 저장하는 변수

	size = (words % 2) ? (words+1) * WSIZE : words * WSIZE;
	// heap을 얼마나 확장할지 정하고 size에 그에 해당하는 값 저장
	if((long)(bp = mem_sbrk(size)) == -1)
		return NULL;
	/* mem_sbrk(size)가 실패시 -1을 반환하므로 이 경우에는
	 * heap을 늘리는 것도 실패이므로 NULL을 반환한다.
	 * 성공시에 bp에는 이전 주소포인터가 담긴다.
	 */

	PUT(HDRP(bp), PACK(size,0));
	// hdr에 해당하는 주소번지에 size값을 넣어주고 free상태로 저장
	PUT(FTRP(bp), PACK(size,0));
	// ftr에 해당하는 주소번지에 size값을 넣어주고 free상태로 저장
	PUT(HDRP(NEXT_BLKP(bp)), PACK(0,1));
	// 그다음 hdr에 해당하는 주소번지에 alloc상태로 저장
	return coalesce(bp); // 주소 bp에 대해 병합함수 실행
}

static void place(void *bp, size_t asize) {
	size_t csize = GET_SIZE(HDRP(bp));
	// bp의 hdr의 size에 해당하는 값을 csize에 저장
	if((csize-asize) >= (OVERHEAD+DSIZE)) {
		/* csize-asize값이 OVERHEAD+DSIZE값보다 크거나 같은 경우에는
		 * bp위치에 asize 크기의 메모리를 위치시킨다.
		 */
		PUT(HDRP(bp), PACK(asize,1));
		PUT(FTRP(bp), PACK(asize,1));
		/* bp에 asize 크기의 블록을 할당함 bp에 대하여 hdr와 ftr에
		 * asize+1 값을 넣어 asize만큼의 크기를 할당하고 alloc한다.
		 */
		bp = NEXT_BLKP(bp);
		// bp에 대하여 다음 block의 주소를 계산하고 그 값을 bp에 저장
		PUT(HDRP(bp), PACK(csize-asize,0));
		PUT(FTRP(bp), PACK(csize-asize,0));
		/* 여기서의 bp는 이전 bp와는 다른 bp이다. 현재의 bp는 이전 bp에서
		 * 다음 블럭에 해당하는 bp이다. 이 bp에 해당하는 hdr과 ftr에
		 * csize-asize값을 넣어주고 저장한다
		 */
	}
	else{
		/* csize-asize가 OVERHEAD+DSIZE보다 작은 경우에는 bp에 대하여 hdr과
		 * ftr에 size를 csize값으로 갖게하고 alloc 시켜준다.
		 */
		PUT(HDRP(bp), PACK(csize,1));
		PUT(FTRP(bp), PACK(csize,1));
	}
}

static void *coalesce(void *bp) {
	//size_t prev_alloc = GET_ALLOC(FTRP(PREV_BLKP(bp)));
	size_t prev_alloc = GET_ALLOC(bp-DSIZE);
	/* 이전 블록이 free인지 보기 위해서 bp-DSIZE는 이전 블록의 ftr이므로
	 * bp-DSIZE에 해당하는 주소에서 GET_ALLOC함수를 실행해보면 alloc인지
	 * free인지 그 값이 나오는데 그 값을 저장한다.
	 */
	//size_t next_alloc = GET_ALLOC(HDRP(NEXT_BLKP(bp)));
	size_t next_alloc = GET_ALLOC(FTRP(bp)+WSIZE);
	/* 다음 블록은 현재 bp의 ftr에서 + WSIZE한 값만큼의 주소에 있는데,
	 * GET_ALLOC을 이용하여 다음 블록의 헤더에 있는 값을 확인해 free인지
	 * alloc인지에 대한 값을 저장한다.
	 */
	size_t size = GET_SIZE(HDRP(bp));
	// bp의 hdr에 저장되어있는 size값을 GET_SIZE함수를 이용해 size에 저장

	if(prev_alloc && next_alloc) {
		// 이전 블록과 다음 블록이 모두 alloc인 경우 현재 bp를 반환
		// 합칠 블록이 없는 경우에 해당한다.
		return bp;
	}
	else if(prev_alloc && !next_alloc) {
		// 이전블록은 alloc이고 다음 블록은 free인 경우
		size += GET_SIZE(HDRP(NEXT_BLKP(bp)));
		PUT(HDRP(bp), PACK(size,0));
		PUT(FTRP(bp), PACK(size,0));
	}
	else if(!prev_alloc && next_alloc) {
		// 이전 블록은 free이고 다음 블록이 alloc인 경우
		size += GET_SIZE(HDRP(PREV_BLKP(bp)));
		PUT(FTRP(bp), PACK(size,0));
		PUT(HDRP(PREV_BLKP(bp)), PACK(size,0));
		bp = PREV_BLKP(bp);
	}
	else {
		// 이전 블록과 다음 블록이 모두 free인 경우
		size += GET_SIZE(HDRP(PREV_BLKP(bp))) + GET_SIZE(FTRP(NEXT_BLKP(bp)));
		PUT(HDRP(PREV_BLKP(bp)), PACK(size,0));
		PUT(FTRP(NEXT_BLKP(bp)), PACK(size,0));
		bp = PREV_BLKP(bp);
	}

	return bp;
}

static void *find_fit(size_t asize) {
	/* asize(사이즈)값에 맞는 메모리 공간을 찾아서 그 주소를 반환해주는 함수 (베이스 : Next fit)*/
	char *bp = find_point; // 찾는 지점
	char *best = 0; // 최적의 주소를 저장할 포인터 변수
	int i = 0; // count 변수
	for (; GET_SIZE(HDRP(bp)) > 0; bp = NEXT_BLKP(bp)) {
		if (!GET_ALLOC(HDRP(bp)) && (asize <= GET_SIZE(HDRP(bp)))) {
			best = bp;
				for (; GET_SIZE(HDRP(bp)) > 0 && i < 70; ++i, bp = NEXT_BLKP(bp)) {
					// 조금 더 탐색하여 최적의 값이 있는지 확인
					if (!GET_ALLOC(HDRP(bp)) && asize <= GET_SIZE(HDRP(bp))) {
						if (GET_SIZE(HDRP(best)) > GET_SIZE(HDRP(bp)))
							best = bp;

						if (GET_SIZE(HDRP(best)) == asize)
							break;
					}
				}
			find_point = best;
			return best;
		}
	}
	// 처음으로 돌아가서 그 부분부터 다시 탐색(시간은 더 걸리지만 util이 올라간다.)
	for (bp = heap_listp; bp < find_point; bp = NEXT_BLKP(bp))
		// 조금 더 탐색하여 최적의 값이 있는지 확인
		if (!GET_ALLOC(HDRP(bp)) && (asize <= GET_SIZE(HDRP(bp)))) {
			best = bp;
			find_point = best;
			return best;
	}
	return NULL;
}
//
/*
 * malloc
 */
void *malloc (size_t size) {
	// size값에 대해서 알맞게 크기를 조정한 후 그 크기만큼 메모리 공간을 할당해주는 함수
	size_t asize;
	size_t extendsize;

	char *bp;
	if(size == 0)
		return NULL;

	if(size <= DSIZE) // 양방향 연결이므로 HDR과 FTR만 해도 8바이트 이므로 8 이하의 비트를 요구할 시 16바이트를 할당해주어야 한다
		asize = 2*DSIZE;
	else // 양방향 연결임을 고려해 9바이트 이상 할당시의 일반화된 공식을 통해 그 크기만큼 할당한다
		asize = DSIZE * ((size + (DSIZE) + (DSIZE - 1)) / DSIZE);

	if((bp = find_fit(asize)) != NULL) { // find_fit을 성공한 경우
		place(bp, asize); // 찾은 주소 공간에 그 크기만큼 할당
		return bp;
	}

	extendsize = MAX(asize, CHUNKSIZE); // 힙 확장할 크기 선택
	if((bp = extended_heap(extendsize/WSIZE)) == NULL) // 힙 확장 실패시
		return NULL;

	place(bp, asize); // 힙이 확장된 첫 부분에 그 크기만큼 할당
	return bp;
}//

/*
 * free
 */
void free (void *ptr) {
	// 메모리 할당을 풀어주는 함수
	if(!ptr) return; // 주소값이 0인 경우 함수 종료
	size_t size = GET_SIZE(HDRP(ptr)); // HDR의 size저wkd

	// HDR과 FTR에 size값을 넣어주고 not alloc임을 저장한다
	PUT(HDRP(ptr), PACK(size, 0));
	PUT(FTRP(ptr), PACK(size, 0));
	find_point = coalesce(ptr); // 병합 실행
}

/*
 * realloc - you may want to look at mm-naive.c
 */
void *realloc(void *oldptr, size_t size) {
	// 재할당하는 함수
	size_t oldsize;
	void *newptr;

	if(size ==0){
		// size가 0인경우 free실행
		free(oldptr);
		return 0;
	}
	if(oldptr == NULL) {
		// oldptr이 NULL인경우 malloc함수 실행
		return malloc(size);
	}
	newptr = malloc(size); // malloc 함수 실행후 return값을 newptr에 저장

	if(!newptr) { // newptr이 0인 경우 0반환후 종료
		return 0;
	}

	oldsize = *SIZE_PTR(oldptr);

	if(size < oldsize)
		oldsize = size;

	memcpy(newptr,oldptr,oldsize);

	free(oldptr);

	return newptr;

}

/*
 * calloc - you may want to look at mm-naive.c
 * This function is not tested by mdriver, but it is
 * needed to run the traces.

 */
void *calloc (size_t nmemb, size_t size) {
 	size_t bytes = nmemb * size;
	void *newptr;

	newptr = malloc(bytes);
	memset(newptr,0,bytes);
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
