#include <threads.h>

enum { Q_OK, Q_ERROR };

typedef struct { /* Queue node */
    void *value;
    void *next;
} node_t;

typedef struct { /* Two lock queue */
    node_t *first, *last;
    mtx_t *first_mutex, *last_mutex;
} con_queue_t;

/* Free the queue struct. It assumes that the queue is depleted, and it will
 * not manage allocated elements inside of it.
 */
void con_free(con_queue_t *);

#include <stdlib.h>
#include <string.h>

inline static node_t *_con_node_init(void *value)
{
    node_t *node = malloc(sizeof(node_t));
    if (!node)
        return NULL;

    node->value = value;
    node->next = NULL;

    return node;
}

/* Allocates and initializes queue.
 * Returns a pointer to an allocated struct for the synchronized queue or NULL
 * on failure.
 */
con_queue_t *con_init()
{
    /* Allocate queue */
    con_queue_t *queue = malloc(sizeof(con_queue_t));
    if (!queue)
        return NULL;

    if ((queue->first_mutex = malloc(sizeof(mtx_t))) == NULL) {
        free(queue);
        return NULL;
    }
    if ((queue->last_mutex = malloc(sizeof(mtx_t))) == NULL) {
        free(queue->first_mutex);
        free(queue);
        return NULL;
    }

    if (mtx_init(queue->first_mutex, mtx_plain) != thrd_success ||
        mtx_init(queue->last_mutex, mtx_plain) != thrd_success) {
        con_free(queue);
        return NULL;
    }

    node_t *dummy = _con_node_init(NULL);
    if (!dummy) {
        con_free(queue);
        return NULL;
    }

    queue->first = queue->last = dummy;

    return queue;
}

void con_free(con_queue_t *queue)
{
    if (!queue)
        return;

    if (!queue->first)
        free(queue->first);

    if (queue->first_mutex) {
        mtx_destroy(queue->first_mutex);
        free(queue->first_mutex);
    }
    if (queue->last_mutex) {
        mtx_destroy(queue->last_mutex);
        free(queue->last_mutex);
    }

    free(queue);
}

/* Add element to queue. The client is responsible for freeing elementsput into
 * the queue afterwards. Returns Q_OK on success or Q_ERROR on failure.
 */
int con_push(con_queue_t *restrict queue, void *restrict new_element)
{
    /* Prepare new node */
    node_t *node = _con_node_init(new_element);
    if (!node)
        return Q_ERROR;

    /* Add to queue with lock */
    mtx_lock(queue->last_mutex);
    queue->last->next = node;
    queue->last = node;
    mtx_unlock(queue->last_mutex);

    return Q_OK;
}

/* Retrieve element and remove it from the queue.
 * Returns a pointer to the element previously pushed in or NULL of the queue is
 * emtpy.
 */
void *con_pop(con_queue_t *queue)
{
    mtx_lock(queue->first_mutex);

    node_t *node = queue->first;             /* Node to be removed */
    node_t *new_header = queue->first->next; /* become the first in the queue */

    /* Queue is empty */
    if (!new_header) {
        mtx_unlock(queue->first_mutex);
        return NULL;
    }

    /* Queue not empty: retrieve data and rewire */
    void *return_value = node->value;
    queue->first = node->next;

    mtx_unlock(queue->first_mutex);

    /* Free removed node and return */
    free(node);
    return return_value;
}

#include <assert.h>
#include <stdio.h>

#define N_PUSH_THREADS 4
#define N_POP_THREADS 4
#define NUM 1000000

/* This thread writes integers into the queue */
int push_thread(void *queue_ptr)
{
    con_queue_t *queue = (con_queue_t *) queue_ptr;

    /* Push ints into queue */
    for (int i = 0; i < NUM; ++i) {
        int *pushed_value = malloc(sizeof(int));
        *pushed_value = i;
        if (con_push(queue, pushed_value) != Q_OK)
            printf("Error pushing element %i\n", i);
    }

    thrd_exit(0);
}

/* This thread reads ints from the queue and frees them */
int pop_thread(void *queue_ptr)
{
    con_queue_t *queue = (con_queue_t *) queue_ptr;

    /* Read values from queue. Break loop on -1 */
    while (1) {
        int *popped_value = con_pop(queue);
        if (popped_value) {
            if (*popped_value == -1) {
                free(popped_value);
                break;
            }

            free(popped_value);
        }
    }

    thrd_exit(0);
}

int main()
{
    thrd_t push_threads[N_PUSH_THREADS], pop_threads[N_POP_THREADS];

    con_queue_t *queue = con_init();

    for (int i = 0; i < N_PUSH_THREADS; ++i) {
        if (thrd_create(&push_threads[i], push_thread, queue) != thrd_success)
            printf("Error creating push thread %i\n", i);
    }

    for (int i = 0; i < N_POP_THREADS; ++i) {
        if (thrd_create(&pop_threads[i], pop_thread, queue) != thrd_success)
            printf("Error creating pop thread %i\n", i);
    }

    for (int i = 0; i < N_PUSH_THREADS; ++i) {
        if (thrd_join(push_threads[i], NULL) != thrd_success)
            continue;
    }

    /* Push kill signals */
    for (int i = 0; i < N_POP_THREADS; ++i) {
        int *kill_signal = malloc(sizeof(int)); /* signal pop threads to exit */
        *kill_signal = -1;
        con_push(queue, kill_signal);
    }

    for (int i = 0; i < N_POP_THREADS; ++i) {
        if (thrd_join(pop_threads[i], NULL) != thrd_success)
            continue;
    }

    con_free(queue);
    return 0;
}
