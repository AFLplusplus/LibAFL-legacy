#include "libmutator.h"

mutator_t *afl_mutator_init(stage_t *stage) {

  mutator_t *mutator = ck_alloc(sizeof(mutator_t));

  mutator->stage = stage;
  mutator->functions = ck_alloc(sizeof(struct mutator_functions));

  mutator->functions->get_stage = _get_mutator_stage_;

  return mutator;

}

void afl_mutator_deinit(mutator_t *mutator) {

  ck_free(mutator->functions);
  ck_free(mutator);

}

stage_t *_get_mutator_stage_(mutator_t *mutator) {

  return mutator->stage;

}

scheduled_mutator_t *afl_scheduled_mutator_init(stage_t *stage) {

  scheduled_mutator_t *sched_mut = ck_alloc(sizeof(scheduled_mutator_t));
  sched_mut->super = *(afl_mutator_init(stage));
  sched_mut->extra_functions = ck_alloc(sizeof(struct scheduled_mutator_functions));

  sched_mut->extra_functions->add_mutator = _add_mutator_;
  sched_mut->extra_functions->iterations = _iterations_;
  sched_mut->extra_functions->schedule = _schedule_;

  return sched_mut;

}

void afl_scheduled_mutator_deinit(scheduled_mutator_t *mutator) {

  LIST_FOREACH_CLEAR(&(mutator->mutations), mutator_func_type, {});

  ck_free(mutator->extra_functions);
  ck_free(mutator);

}

void _add_mutator_(scheduled_mutator_t *mutator,
                   mutator_func_type    mutator_func) {

  list_append(&(mutator->mutations), mutator_func);

}

