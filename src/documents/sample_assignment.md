# D.1. Sample Assignment
* Implement thread_join().

## Function: `void thread_join (tid_t tid)`

* Blocks the current thread until thread tid exits. If A is the running thread and B is the argument, then we say that "A joins B."
* Incidentally, the argument is a thread id, instead of a thread pointer, because a thread pointer is not unique over time.  That is, when a thread dies, its memory may be, whether immediately or much later, reused for another thread.  If thread A over time had two children B and C that were stored at the same address, then thread_join(B) and thread_join(C) would be ambiguous.

* A thread may only join its immediate children. Calling thread_join() on a thread that is not the caller's child should cause the caller to return immediately. Children are not "inherited," that is, if A has child B and B has child C, then A always returns immediately should it try to join C, even if B is dead.

* A thread need not ever be joined. Your solution should properly free all of a thread's resources, including its struct thread, whether it is ever joined or not, and regardless of whether the child exits before or after its parent. That is, a thread should be freed exactly once in all cases.

* Joining a given thread is idempotent. That is, joining a thread multiple times is equivalent to joining it once, because it has already exited at the time of the later joins. Thus, joins on a given thread after the first should return immediately.

* You must handle all the ways a join can occur: nested joins (A joins B, then B joins C), multiple joins (A joins B, then A joins C), and so on.
