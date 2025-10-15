#include "bitmap.h"
#include <debug.h>
#include <limits.h>
#include <round.h>
#include <stdio.h>
#include "threads/malloc.h"
#ifdef FILESYS
#include "filesys/file.h"
#endif

/* 원소 타입.

   이것은 최소한 int만큼 넓은 부호 없는 정수 타입이어야 합니다.

   각 비트는 비트맵의 한 비트를 나타냅니다.
   만약 한 원소의 0번 비트가 비트맵의 K번 비트를 나타낸다면,
   그 원소의 1번 비트는 비트맵의 K+1번 비트를 나타내는 식입니다. */
typedef unsigned long elem_type;

/* 원소의 비트 수. */
#define ELEM_BITS (sizeof(elem_type) * CHAR_BIT)

/* 외부에서 보면, 비트맵은 비트의 배열입니다. 내부적으로는,
   비트 배열을 시뮬레이션하는 elem_type(위에 정의됨)의 배열입니다. */
struct bitmap
{
    size_t bit_cnt;  /* 비트의 수. */
    elem_type *bits; /* 비트를 나타내는 원소들. */
};

/* BIT_IDX 번호의 비트를 포함하는 원소의 인덱스를 반환합니다. */
static inline size_t elem_idx(size_t bit_idx)
{
    return bit_idx / ELEM_BITS;
}

/* BIT_IDX에 해당하는 비트만 켜진 elem_type을 반환합니다. */
static inline elem_type bit_mask(size_t bit_idx)
{
    return (elem_type)1 << (bit_idx % ELEM_BITS);
}

/* BIT_CNT 개의 비트에 필요한 원소의 수를 반환합니다. */
static inline size_t elem_cnt(size_t bit_cnt)
{
    return DIV_ROUND_UP(bit_cnt, ELEM_BITS);
}

/* BIT_CNT 개의 비트에 필요한 바이트 수를 반환합니다. */
static inline size_t byte_cnt(size_t bit_cnt)
{
    return sizeof(elem_type) * elem_cnt(bit_cnt);
}

/* B의 bits의 마지막 원소에서 실제로 사용되는 비트들이 1로 설정되고
   나머지는 0으로 설정된 비트 마스크를 반환합니다. */
static inline elem_type last_mask(const struct bitmap *b)
{
    int last_bits = b->bit_cnt % ELEM_BITS;
    return last_bits ? ((elem_type)1 << last_bits) - 1 : (elem_type)-1;
}

/* Creation and destruction. */

/* B를 BIT_CNT 비트의 비트맵으로 초기화하고
   모든 비트를 false로 설정합니다.
   성공하면 true, 메모리 할당에 실패하면 false를 반환합니다. */
struct bitmap *bitmap_create(size_t bit_cnt)
{
    struct bitmap *b = malloc(sizeof *b);
    if (b != NULL)
    {
        b->bit_cnt = bit_cnt;
        b->bits = malloc(byte_cnt(bit_cnt));
        if (b->bits != NULL || bit_cnt == 0)
        {
            bitmap_set_all(b, false);
            return b;
        }
        free(b);
    }
    return NULL;
}

/* BLOCK에 미리 할당된 BLOCK_SIZE 바이트의 저장 공간에
   BIT_CNT 비트를 가진 비트맵을 생성하고 반환합니다.
   BLOCK_SIZE는 최소한 bitmap_buf_size(BIT_CNT)여야 합니다. */
struct bitmap *bitmap_create_in_buf(size_t bit_cnt, void *block, size_t block_size UNUSED)
{
    struct bitmap *b = block;

    ASSERT(block_size >= bitmap_buf_size(bit_cnt));

    b->bit_cnt = bit_cnt;
    b->bits = (elem_type *)(b + 1);
    bitmap_set_all(b, false);
    return b;
}

/* BIT_CNT 비트를 가진 비트맵을 수용하는 데 필요한 바이트 수를 반환합니다
   (bitmap_create_in_buf()와 함께 사용). */
size_t bitmap_buf_size(size_t bit_cnt)
{
    return sizeof(struct bitmap) + byte_cnt(bit_cnt);
}

/* 비트맵 B를 파괴하고 저장 공간을 해제합니다.
   bitmap_create_in_buf()로 생성된 비트맵에는 사용하지 않습니다. */
void bitmap_destroy(struct bitmap *b)
{
    if (b != NULL)
    {
        free(b->bits);
        free(b);
    }
}

/* Bitmap size. */

/* B에 있는 비트의 수를 반환합니다. */
size_t bitmap_size(const struct bitmap *b)
{
    return b->bit_cnt;
}

/* 단일 비트 설정 및 테스트. */

/* B에서 IDX 번호의 비트를 VALUE로 원자적으로 설정합니다. */
void bitmap_set(struct bitmap *b, size_t idx, bool value)
{
    ASSERT(b != NULL);
    ASSERT(idx < b->bit_cnt);
    if (value)
        bitmap_mark(b, idx);
    else
        bitmap_reset(b, idx);
}

/* Atomically sets the bit numbered BIT_IDX in B to true. */
void bitmap_mark(struct bitmap *b, size_t bit_idx)
{
    size_t idx = elem_idx(bit_idx);
    elem_type mask = bit_mask(bit_idx);

    /* 이것은 `b->bits[idx] |= mask'와 동일하지만
       단일 프로세서 시스템에서 원자적임을 보장합니다.
       [IA32-v2b]의 OR 명령어 설명을 참조하세요. */
    asm("lock orq %1, %0" : "=m"(b->bits[idx]) : "r"(mask) : "cc");
}

/* Atomically sets the bit numbered BIT_IDX in B to false. */
void bitmap_reset(struct bitmap *b, size_t bit_idx)
{
    size_t idx = elem_idx(bit_idx);
    elem_type mask = bit_mask(bit_idx);

    /* 이것은 `b->bits[idx] &= ~mask'와 동일하지만
       단일 프로세서 시스템에서 원자적임을 보장합니다.
       [IA32-v2a]의 AND 명령어 설명을 참조하세요. */
    asm("lock andq %1, %0" : "=m"(b->bits[idx]) : "r"(~mask) : "cc");
}

/* B에서 IDX 번호의 비트를 원자적으로 토글합니다;
   즉, true이면 false로 만들고,
   false이면 true로 만듭니다. */
void bitmap_flip(struct bitmap *b, size_t bit_idx)
{
    size_t idx = elem_idx(bit_idx);
    elem_type mask = bit_mask(bit_idx);

    /* 이것은 `b->bits[idx] ^= mask'와 동일하지만
       단일 프로세서 시스템에서 원자적임을 보장합니다.
       [IA32-v2b]의 XOR 명령어 설명을 참조하세요. */
    asm("lock xorq %1, %0" : "=m"(b->bits[idx]) : "r"(mask) : "cc");
}

/* Returns the value of the bit numbered IDX in B. */
bool bitmap_test(const struct bitmap *b, size_t idx)
{
    ASSERT(b != NULL);
    ASSERT(idx < b->bit_cnt);
    return (b->bits[elem_idx(idx)] & bit_mask(idx)) != 0;
}

/* 다중 비트 설정 및 테스트. */

/* B의 모든 비트를 VALUE로 설정합니다. */
void bitmap_set_all(struct bitmap *b, bool value)
{
    ASSERT(b != NULL);

    bitmap_set_multiple(b, 0, bitmap_size(b), value);
}

/* Sets the CNT bits starting at START in B to VALUE. */
void bitmap_set_multiple(struct bitmap *b, size_t start, size_t cnt, bool value)
{
    size_t i;

    ASSERT(b != NULL);
    ASSERT(start <= b->bit_cnt);
    ASSERT(start + cnt <= b->bit_cnt);

    for (i = 0; i < cnt; i++)
        bitmap_set(b, start + i, value);
}

/* START와 START + CNT 사이(exclusive)에 있는 B의 비트들 중
   VALUE로 설정된 비트의 수를 반환합니다. */
size_t bitmap_count(const struct bitmap *b, size_t start, size_t cnt, bool value)
{
    size_t i, value_cnt;

    ASSERT(b != NULL);
    ASSERT(start <= b->bit_cnt);
    ASSERT(start + cnt <= b->bit_cnt);

    value_cnt = 0;
    for (i = 0; i < cnt; i++)
        if (bitmap_test(b, start + i) == value)
            value_cnt++;
    return value_cnt;
}

/* START와 START + CNT 사이(exclusive)에 있는 B의 비트들 중
   VALUE로 설정된 비트가 하나라도 있으면 true, 그렇지 않으면 false를 반환합니다. */
bool bitmap_contains(const struct bitmap *b, size_t start, size_t cnt, bool value)
{
    size_t i;

    ASSERT(b != NULL);
    ASSERT(start <= b->bit_cnt);
    ASSERT(start + cnt <= b->bit_cnt);

    for (i = 0; i < cnt; i++)
        if (bitmap_test(b, start + i) == value)
            return true;
    return false;
}

/* START와 START + CNT 사이(exclusive)에 있는 B의 비트들 중
   true로 설정된 비트가 하나라도 있으면 true, 그렇지 않으면 false를 반환합니다.*/
bool bitmap_any(const struct bitmap *b, size_t start, size_t cnt)
{
    return bitmap_contains(b, start, cnt, true);
}

/* START와 START + CNT 사이(exclusive)에 있는 B의 비트들 중
   true로 설정된 비트가 하나도 없으면 true, 그렇지 않으면 false를 반환합니다.*/
bool bitmap_none(const struct bitmap *b, size_t start, size_t cnt)
{
    return !bitmap_contains(b, start, cnt, true);
}

/* START와 START + CNT 사이(exclusive)에 있는 B의 모든 비트가
   true로 설정되어 있으면 true, 그렇지 않으면 false를 반환합니다. */
bool bitmap_all(const struct bitmap *b, size_t start, size_t cnt)
{
    return !bitmap_contains(b, start, cnt, false);
}

/* 설정되거나 설정되지 않은 비트 찾기. */

/* B에서 START 이후에 나오는, 모두 VALUE로 설정된 CNT개의
   연속된 비트 그룹의 시작 인덱스를 찾아 반환합니다.
   그러한 그룹이 없으면 BITMAP_ERROR를 반환합니다. */
size_t bitmap_scan(const struct bitmap *b, size_t start, size_t cnt, bool value)
{
    ASSERT(b != NULL);
    ASSERT(start <= b->bit_cnt);

    if (cnt <= b->bit_cnt)
    {
        size_t last = b->bit_cnt - cnt;
        size_t i;
        for (i = start; i <= last; i++)
            if (!bitmap_contains(b, i, cnt, !value))
                return i;
    }
    return BITMAP_ERROR;
}

/* B에서 START 이후에 나오는, 모두 VALUE로 설정된 CNT개의
   연속된 비트 그룹을 찾아, 그 비트들을 모두 !VALUE로 뒤집고,
   그룹의 첫 번째 비트 인덱스를 반환합니다.
   그러한 그룹이 없으면 BITMAP_ERROR를 반환합니다.
   CNT가 0이면 0을 반환합니다.
   비트 설정은 원자적이지만, 비트 테스트와 설정은 원자적으로 함께 이루어지지 않습니다. */
size_t bitmap_scan_and_flip(struct bitmap *b, size_t start, size_t cnt, bool value)
{
    size_t idx = bitmap_scan(b, start, cnt, value);
    if (idx != BITMAP_ERROR)
        bitmap_set_multiple(b, idx, cnt, !value);
    return idx;
}

/* 파일 입출력. */

#ifdef FILESYS
/* B를 파일에 저장하는 데 필요한 바이트 수를 반환합니다. */
size_t bitmap_file_size(const struct bitmap *b)
{
    return byte_cnt(b->bit_cnt);
}

/* FILE에서 B를 읽습니다. 성공하면 true, 그렇지 않으면 false를 반환합니다. */
bool bitmap_read(struct bitmap *b, struct file *file)
{
    bool success = true;
    if (b->bit_cnt > 0)
    {
        off_t size = byte_cnt(b->bit_cnt);
        success = file_read_at(file, b->bits, size, 0) == size;
        b->bits[elem_cnt(b->bit_cnt) - 1] &= last_mask(b);
    }
    return success;
}

/* B를 FILE에 씁니다. 성공하면 true, 그렇지 않으면 false를 반환합니다. */
bool bitmap_write(const struct bitmap *b, struct file *file)
{
    off_t size = byte_cnt(b->bit_cnt);
    return file_write_at(file, b->bits, size, 0) == size;
}
#endif /* FILESYS */

/* 디버깅. */

/* B의 내용을 16진수로 콘솔에 덤프합니다. */
void bitmap_dump(const struct bitmap *b)
{
    hex_dump(0, b->bits, byte_cnt(b->bit_cnt), false);
}
