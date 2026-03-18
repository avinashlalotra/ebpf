#include "maps.h"

struct InodeMap_t InodeMap SEC(".maps");
struct RingbufMap_t rb SEC(".maps");
struct LruMap_t LruMap SEC(".maps");
struct heap_map_t heap_map SEC(".maps");

char _license[] SEC("license") = "GPL";