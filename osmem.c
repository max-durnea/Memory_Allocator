// SPDX-License-Identifier: BSD-3-Clause
#include "osmem.h"
#include <unistd.h>
#include <sys/mman.h>
#include <string.h>
#include "block_meta.h"

#define MMAP_THRESHOLD 131072
#define METADATA_SIZE sizeof(struct block_meta)

struct block_meta *first_block;
char first_brk;

int flag1 = PROT_READ|PROT_WRITE;
int flag2 = MAP_PRIVATE|MAP_ANONYMOUS;

// connect free blocks at the start
// add flag to check for first brk
// if last block is free, expand it
// if not a single block free, expand the heap
// fix split block


void add_to_list(struct block_meta *start, struct block_meta *block)
{
	struct block_meta *temp = start;

	while (temp->next != NULL)
		temp = temp->next;
	temp->next = block;
	block->prev = temp;
	block->next = NULL;
}

void create_meta(struct block_meta *block, size_t size, int status, struct block_meta *prev, struct block_meta *next)
{
	block->size = size;
	block->status = status;
	block->prev = prev;
	block->next = next;
}

struct block_meta *find_best_fitting_block(struct block_meta *start, size_t padded_size, int realloc)
{
	struct block_meta *best_so_far = NULL;
	struct block_meta *temp = start;

	while (temp->next != NULL) {
		if (temp->status == STATUS_FREE) {
			if (temp->size == padded_size)
				return temp;
			else if (temp->size > padded_size && (best_so_far == NULL || temp->size < best_so_far->size))
				best_so_far = temp;
		}
		temp = temp->next;
	}
	if (temp->status == STATUS_FREE) {
		if (temp->size == padded_size) {
			return temp;
		} else if (temp->size > padded_size && (best_so_far == NULL || temp->size < best_so_far->size)) {
			best_so_far = temp;
		} else if (temp->size < padded_size && !realloc) {
			// Expand the heap
			sbrk(padded_size - temp->size);
			temp->size = padded_size;
			return temp;
		}
	}
	return best_so_far;
}

struct block_meta *split_block(struct block_meta *block, size_t padded_size)
{
	if (block->size - padded_size < (METADATA_SIZE + 8))
		return block;
	struct block_meta *next_block = (struct block_meta *)((char *)block + padded_size + METADATA_SIZE);

	create_meta(next_block, block->size - padded_size - METADATA_SIZE, STATUS_FREE, block, block->next);
	block->size = padded_size;
	block->next = next_block;
	return block;
}
void connect_free_blocks(struct block_meta *start)
{
	struct block_meta *temp = start;

	if (temp == NULL)
		return;
	while (temp->next != NULL) {
		if (temp->status == STATUS_FREE && temp->next->status == STATUS_FREE) {
			temp->size += temp->next->size + METADATA_SIZE;
			temp->next = temp->next->next;
			if (temp->next != NULL)
				temp->next->prev = temp;
		} else {
			temp = temp->next;
		}
	}
}
void *os_malloc(size_t size)
{
	connect_free_blocks(first_block);
	if (size == 0)
		return NULL;
	// PAD THE SIZE
	size_t padded_size = (size + 7) & ~7;
	// CASE 1 BRK
	if (padded_size + METADATA_SIZE < MMAP_THRESHOLD) {
		if (first_brk == 0) {
			first_brk = 1;
			first_block = (struct block_meta *)sbrk(MMAP_THRESHOLD);
			create_meta(first_block, MMAP_THRESHOLD - METADATA_SIZE, STATUS_FREE, NULL, NULL);
		}
		struct block_meta *best_fit = find_best_fitting_block(first_block, padded_size, 0);

		if (best_fit != NULL) {
			struct block_meta *splitted_block = split_block(best_fit, padded_size);

			splitted_block->status = STATUS_ALLOC;
			return (void *)(splitted_block + 1);
		}
		// Expand the heap
		struct block_meta *temp = first_block;

		while (temp->next != NULL)
			temp = temp->next;
		struct block_meta *new_block = (struct block_meta *)sbrk(padded_size + METADATA_SIZE);

		create_meta(new_block, padded_size, STATUS_ALLOC, temp, NULL);
		temp->next = new_block;
		return (void *)((char *)new_block + METADATA_SIZE);
	} // CASE 2: MMAP ALLOCATION
	void *start = mmap(NULL, padded_size + METADATA_SIZE, flag1, flag2, -1, 0);
	// CREATE THE META FOR PAYLOAD
	struct block_meta *meta = (struct block_meta *)start;

	meta->size = padded_size;
	meta->status = STATUS_MAPPED;
	meta->prev = NULL;
	meta->next = NULL;

	return (void *)(meta + 1);
}

void os_free(void *ptr)
{
	if (ptr == NULL)
		return;

	struct block_meta *meta = (struct block_meta *)ptr - 1;

	if (meta->status == STATUS_ALLOC) {
		meta->status = STATUS_FREE;
	} else if (meta->status == STATUS_MAPPED) {
		size_t total_size = meta->size + METADATA_SIZE;

		munmap(meta, total_size);
	}
}

void *os_calloc(size_t nmemb, size_t size)
{
	connect_free_blocks(first_block);
	size_t total_size = nmemb * size;

	size_t padded_size = (total_size + 7) & ~7;

	if (total_size == 0)
		return NULL;

	size_t page_size = getpagesize();

	void *ptr;

	if (total_size + METADATA_SIZE < page_size) {
		ptr = os_malloc(total_size);
	} else {
		void *start = mmap(NULL, padded_size + METADATA_SIZE, flag1, flag2, -1, 0);

		if (start == MAP_FAILED)
			return NULL;
		struct block_meta *meta = (struct block_meta *)start;

		meta->size = padded_size;
		meta->status = STATUS_MAPPED;
		meta->prev = NULL;
		meta->next = NULL;
		ptr = (void *)(meta + 1);
	}
	if (ptr != NULL)
		memset(ptr, 0, total_size);
	return ptr;
}
void *os_realloc(void *ptr, size_t size)
{
	connect_free_blocks(first_block);

	if (ptr == NULL)
		return os_malloc(size);
	if (size == 0) {
		os_free(ptr);
		return NULL;
	}

	size_t padded_size = (size + 7) & ~7;
	struct block_meta *meta = (struct block_meta *)ptr - 1;

	if (meta->status == STATUS_FREE)
		return NULL;

	if (meta->size == padded_size)
		return ptr;


	if (meta->status == STATUS_ALLOC) {
		if (meta->size > padded_size) {
			split_block(meta, padded_size);
			return ptr;
		} else if (meta->next != NULL && meta->next->status == STATUS_FREE &&
			meta->size + meta->next->size + METADATA_SIZE >= padded_size){
			meta->size += meta->next->size + METADATA_SIZE;
			meta->next = meta->next->next;
			if (meta->next != NULL)
				meta->next->prev = meta;
			split_block(meta, padded_size);
			return ptr;
		} else if (meta->next == NULL) {
			if (sbrk(padded_size - meta->size) == (void *)-1)
				return NULL;
			meta->size = padded_size;
			return ptr;
		}
		struct block_meta *best_fit = find_best_fitting_block(first_block, padded_size, 1);

		if (best_fit != NULL) {
			struct block_meta *splitted_block = split_block(best_fit, padded_size);

			splitted_block->status = STATUS_ALLOC;
			size_t copy_size = meta->size < padded_size ? meta->size : padded_size;

			memcpy((void *)(splitted_block + 1), ptr, copy_size);
			os_free(ptr);
			return (void *)(splitted_block + 1);
		}
	} else if (meta->status == STATUS_MAPPED && padded_size < MMAP_THRESHOLD && first_brk != 0) {
		struct block_meta *best = find_best_fitting_block(first_block, padded_size, 1);

		if (best == NULL) {
			struct block_meta *temp = first_block;

			while (temp->next != NULL)
				temp = temp->next;
			struct block_meta *new_block = (struct block_meta *)sbrk(padded_size + METADATA_SIZE);

			create_meta(new_block, padded_size, STATUS_ALLOC, temp, NULL);
			temp->next = new_block;
			void *new_ptr = (void *)(new_block + 1);
			size_t copy_size = meta->size < padded_size ? meta->size : padded_size;

			memcpy(new_ptr, ptr, copy_size);
			os_free(ptr);
			return new_ptr;
		}
	}

	void *new_ptr = os_malloc(padded_size);
	size_t copy_size = meta->size < padded_size ? meta->size : padded_size;

	memcpy(new_ptr, ptr, copy_size);
	os_free(ptr);
	return new_ptr;
}
