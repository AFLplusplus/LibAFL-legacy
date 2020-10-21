#include "catch.hpp"

#include "corpus/corpus.hpp"
#include "corpus/entry.hpp"
#include "input/bytes.hpp"

TEST_CASE("Corpus can insert", "[Corpus]") {

  u8 buffer[] = {0, 0, 0, 0};
  afl::Entry* entry = new afl::Entry(new afl::BytesInput(buffer, 4));
  afl::RandomState rand(0);
  afl::Corpus corpus(&rand);
  corpus.Insert(entry);

  REQUIRE( corpus.GetEntriesCount() == 1 );
  REQUIRE( corpus.GetByIndex(0) == entry );

}
