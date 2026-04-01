/** Dummy worker to satisfy GRPC_PROXY service binding in tests */
export default {
  async fetch() {
    return new Response("mock grpc proxy", { status: 200 });
  },
};
