#include "corpus/queue.hpp"
#include "corpus/entry.hpp"
#include "input/bytes.hpp"
#include "executor/inmemory.hpp"
#include "observation_channel/hitcounts.hpp"
#include "mutator/havoc.hpp"
#include "feedback/map.hpp"
#include "stage/mutational.hpp"

using namespace afl;

const size_t kMapSize = 65536;

u8 __afl_map[kMapSize];

ExitType Harness(Executor* executor, u8* buffer, size_t size) {

  return ExitType::Ok;

}

int main() {

  RandomState rand(0);
  Corpus corpus(&rand);
  InMemoryExecutor executor(&Harness);
  executor.CreateObservationChannel<HitcountsMapObservationChannel>(__afl_map, kMapSize);
  
  Engine engine(&rand, &executor, &corpus);
  engine.CreateFeedback<HitcountsMapFeedback<kMapSize>>();
  engine.CreateStage<MutationalStage>()->CreateMutator<HavocMutator>();
  
  engine.FuzzOne();
  
  return 0;

}

