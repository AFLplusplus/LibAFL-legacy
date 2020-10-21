#include "corpus/entry.hpp"
#include "corpus/queue.hpp"
#include "executor/inmemory.hpp"
#include "feedback/map.hpp"
#include "input/bytes.hpp"
#include "mutator/havoc.hpp"
#include "observer/hitcounts.hpp"
#include "stage/mutational.hpp"
#include "generator/bytes.hpp"

using namespace afl;

const size_t kMapSize = 65536;

u8 __afl_map[kMapSize];

ExitType Harness(Executor* executor, u8* buffer, size_t size) {
  if (size > 1)
    __afl_map[buffer[0]] = buffer[1];
  return ExitType::kOk;
}

int main() {
  RandomState rand(0);
  Corpus corpus(&rand);
  InMemoryExecutor executor(&Harness);
  executor.CreateObservationChannel<HitcountsMapObservationChannel>(__afl_map,
                                                                    kMapSize);

  Engine engine(&rand, &executor, &corpus);
  engine.CreateFeedback<HitcountsMapFeedback<kMapSize>>();
  engine.CreateStage<MutationalStage>()->CreateMutator<HavocMutator>();

  PrintableGenerator gen(&rand);
  Print(engine.GenerateInputs(&gen, 3).Unwrap());

  size_t cnt = 0;
  while (true) {
    PrintAct("Fuzz interation #", cnt, ", inputs in corpus: ", corpus.GetEntriesCount());
    engine.FuzzOne();
    ++cnt;
  }

  return 0;
}
