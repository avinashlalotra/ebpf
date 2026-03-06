#include "event.hpp"
#include "types.hpp"
#include <bpf/libbpf.h>
#include <cstdio>
#include <cstring>

int callback(void *ctx, void *data, size_t size);
void print_event(EVENT *event);
Packet process_event(EVENT *event);

Events::Events(const struct bpf_map *map) {

  int fd = bpf_map__fd(map);
  if (fd < 0) {
    fprintf(stderr, "Failed to get map fd: %d\n", fd);
    return;
  }

  rb = ring_buffer__new(fd, callback, this, NULL);
  if (!rb) {
    fprintf(stderr, "Failed to create ring buffer\n");
    return;
  }
}

Events::~Events() {
  if (rb)
    ring_buffer__free(rb);
}

void Events::producer() {
  while (!stop_flag) {

    int ret = ring_buffer__poll(rb, 100); // blocking

    if (ret < 0) {
      fprintf(stderr, "ring_buffer__poll error: %d\n", ret);
      break;
    }
  }
}

void Events::consumer() {
  while (!stop_flag) {

    std::unique_lock<std::mutex> lock(queue_mutex);

    queue_cv.wait(lock, [this] { return stop_flag || !event_queue.empty(); });

    if (stop_flag && event_queue.empty())
      return;

    EVENT event = event_queue.front();
    event_queue.pop();

    lock.unlock();

    print_event(&event);
  }
}

void Events::stop() {
  stop_flag = true;
  queue_cv.notify_all(); // wake consumer
}

// push data to queue
int callback(void *ctx, void *data, size_t size) {

  EVENT *event = (EVENT *)data;
  Events *events = (Events *)ctx;

  {
    std::lock_guard<std::mutex> lock(events->queue_mutex);
    events->event_queue.push(*event);
  }

  events->queue_cv.notify_one();

  return 0;
}
#define MAX_PATH_LEN 512
#define PER_LEVEL 32
#define MAX_DEPTH (MAX_PATH_LEN / PER_LEVEL)
void print_event(EVENT *event) {

  printf("Event: uid=%llu, change_type=%u, bytes_written=%u, "
         "before_size=%lld\n",
         (unsigned long long)event->uid, (unsigned int)event->change_type,
         (unsigned int)event->bytes_written, (long long)event->before_size);

  printf("file path: ");

  for (int i = MAX_DEPTH - 1; i >= 0; i--) {
    char *slot = event->filepath + i * PER_LEVEL;
    if (slot[0] == '\0')
      continue;
    printf("/%s", slot);
  }

  printf("\n");
}
