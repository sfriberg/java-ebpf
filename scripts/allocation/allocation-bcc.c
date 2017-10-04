#include <uapi/linux/ptrace.h>

/**
 * Copyright 2017 Staffan Friberg, Medallia
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

struct key {
	u32 pid;
	u64 stack_id;
};

struct data {
	u64 count;
	u64 tlab_size;
	u64 size;
	char type[64];
};

BPF_STACK_TRACE(stacks, 8192)
BPF_HASH(allocation, struct key, struct data);

static int
generate_event(struct pt_regs *ctx, u64 klassHandle, u64 size, u64 tlab_size)
{
	u64 symbol = 0;
	struct key key = {};
	struct data init_data = {};
	struct data *hashed_data;

	key.pid = bpf_get_current_pid_tgid();
	key.stack_id = stacks.get_stackid(ctx, BPF_F_REUSE_STACKID | BPF_F_USER_STACK);

	// Initial data to use if not already hashed
	init_data.count = 0;
	init_data.size = 0;
	init_data.tlab_size = 0;
	// Read name (Symbol) field from KlassHandle
	bpf_probe_read(&symbol, 8, (void *) (klassHandle + 16));
	// Get _body (char *) field from Symbol object
	bpf_probe_read(&(init_data.type), sizeof(init_data.type), (void *) (symbol + 8));

	// Get hashed data and increment
	hashed_data = allocation.lookup_or_init(&key, &init_data);
	hashed_data->count++;
	hashed_data->tlab_size += tlab_size;
	hashed_data->size += size;

	// Return 0 to filter original event, or 1 to forward
	return 0;
}

int alloc_outside_tlab(struct pt_regs *ctx)
{
	// Extract first (KlassHandle) and second (size) function parameters
	return generate_event(ctx, ctx->di, ctx->si, 0);
}

int alloc_in_new_tlab(struct pt_regs *ctx)
{
	// Extract first (KlassHandle), second (tlab size), and third (size) function parameters
	return generate_event(ctx, ctx->di, ctx->dx, ctx->si);
}
