/*
 * Unit tests for cidr-trie.c. Compiled into a standalone binary by the
 * `test-c` Makefile target.
 */
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cidr-trie.h"

static int failures;

#define CHECK(cond, ...)							\
	do {									\
		if (!(cond)) {							\
			fprintf(stderr, "%s:%d: ", __FILE__, __LINE__);		\
			fprintf(stderr, __VA_ARGS__);				\
			fputc('\n', stderr);					\
			failures++;						\
		}								\
	} while (0)

static uint32_t v4(const char *s)
{
	struct in_addr a;
	if (inet_pton(AF_INET, s, &a) != 1) {
		fprintf(stderr, "bad ipv4: %s\n", s);
		exit(2);
	}
	return ntohl(a.s_addr);
}

static void v6(const char *s, uint8_t out[16])
{
	if (inet_pton(AF_INET6, s, out) != 1) {
		fprintf(stderr, "bad ipv6: %s\n", s);
		exit(2);
	}
}

static void test_v4_prefix_match(void)
{
	cidr_trie_t *t = cidr_trie_new();
	CHECK(cidr_trie_insert_str(t, "10.0.0.0/8", 1) == 0,
	      "insert 10.0.0.0/8 failed");
	CHECK(cidr4_trie_lookup(t, v4("10.0.0.1")) == 1,
	      "lookup 10.0.0.1 should be in 10/8");
	CHECK(cidr4_trie_lookup(t, v4("10.255.255.255")) == 1,
	      "lookup 10.255.255.255 should be in 10/8");
	CHECK(cidr4_trie_lookup(t, v4("11.0.0.0")) == 0,
	      "lookup 11.0.0.0 should miss");
	CHECK(cidr4_trie_lookup(t, v4("9.255.255.255")) == 0,
	      "lookup 9.255.255.255 should miss");
}

static void test_v4_host_match(void)
{
	cidr_trie_t *t = cidr_trie_new();
	CHECK(cidr_trie_insert_str(t, "127.0.0.1", 1) == 0,
	      "insert 127.0.0.1 host failed");
	CHECK(cidr4_trie_lookup(t, v4("127.0.0.1")) == 1, "exact host");
	CHECK(cidr4_trie_lookup(t, v4("127.0.0.2")) == 0, "neighbor miss");
}

static void test_v4_zero_prefix(void)
{
	cidr_trie_t *t = cidr_trie_new();
	CHECK(cidr_trie_insert_str(t, "0.0.0.0/0", 1) == 0,
	      "insert default route failed");
	CHECK(cidr4_trie_lookup(t, v4("8.8.8.8")) == 1, "default matches all");
	CHECK(cidr4_trie_lookup(t, v4("1.2.3.4")) == 1, "default matches all");
}

static void test_v6_prefix_match(void)
{
	cidr_trie_t *t = cidr_trie_new();
	uint8_t hit[16], near_hit[16], miss[16];

	CHECK(cidr_trie_insert_str(t, "2001:db8::/32", 1) == 0,
	      "insert 2001:db8::/32 failed");
	v6("2001:db8::1", hit);
	v6("2001:db8:dead:beef::1", near_hit);
	v6("2001:db9::1", miss);
	CHECK(cidr6_trie_lookup(t, hit) == 1, "v6 prefix match exact");
	CHECK(cidr6_trie_lookup(t, near_hit) == 1, "v6 prefix match deep");
	CHECK(cidr6_trie_lookup(t, miss) == 0, "v6 just outside prefix");
}

static void test_v6_host_match(void)
{
	cidr_trie_t *t = cidr_trie_new();
	uint8_t hit[16], miss[16];

	CHECK(cidr_trie_insert_str(t, "::1", 1) == 0, "insert ::1 failed");
	v6("::1", hit);
	v6("::2", miss);
	CHECK(cidr6_trie_lookup(t, hit) == 1, "v6 host match");
	CHECK(cidr6_trie_lookup(t, miss) == 0, "v6 host neighbor miss");
}

static void test_invalid_input_rejected(void)
{
	cidr_trie_t *t = cidr_trie_new();
	CHECK(cidr_trie_insert_str(t, "garbage", 1) < 0, "garbage accepted");
	CHECK(cidr_trie_insert_str(t, "10.0.0.0/33", 1) < 0,
	      "out-of-range prefix accepted");
	CHECK(cidr_trie_insert_str(t, "::1/129", 1) < 0,
	      "out-of-range v6 prefix accepted");
	CHECK(cidr_trie_insert_str(t, "10.0.0.0/-1", 1) < 0,
	      "negative prefix accepted");
}

static void test_v4_mapped_in_v6_table_does_not_match_v4(void)
{
	cidr_trie_t *t = cidr_trie_new();
	uint8_t mapped[16];

	CHECK(cidr_trie_insert_str(t, "10.0.0.0/8", 1) == 0, "insert v4 prefix");
	v6("::ffff:10.0.0.5", mapped);
	/*
	 * cidr_trie keeps v4 and v6 entries in separate tries; a v4 prefix
	 * insertion must not visibly match through the v6 lookup path.
	 */
	CHECK(cidr6_trie_lookup(t, mapped) == 0,
	      "v4 prefix should not bleed into v6 lookups");
}

int main(void)
{
	test_v4_prefix_match();
	test_v4_host_match();
	test_v4_zero_prefix();
	test_v6_prefix_match();
	test_v6_host_match();
	test_invalid_input_rejected();
	test_v4_mapped_in_v6_table_does_not_match_v4();

	if (failures != 0) {
		fprintf(stderr, "%d cidr-trie test(s) failed\n", failures);
		return 1;
	}
	puts("cidr-trie tests passed");
	return 0;
}
