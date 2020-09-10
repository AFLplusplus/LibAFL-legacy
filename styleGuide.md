
# Here is the code format style that is followed in this codebase

## Function and struct member Names

1. Most of the structs here follow a simple way of naming. Although it may differ sometimes, the structs exposed for the user are `type defined (using the keyword typedef)` as *struct_name_**t***. A simple example is

```C
typedef struct afl_raw_input {

  u8 *   bytes;
  size_t len;

  struct raw_input_functions *functions;

} afl_raw_input_t;
```

The structs which aren't `type defined` are meant mostly for the internal use by the library. And the user need not play with it themself.

2. Most of the structs implemented here have a `vtable struct` and the name of this `vtable struct` is *name_of_orig_struct_**functions***, e.g for `struct queue_entry` the vtable is `struct queue_entry_functions`

3. For the vtable, many of the functions have a default implementation that is provided for each function (if we see it fit). The name of these functions start and end with an `_` e.g `_get_queue_size_`, so users can know this is the default behaviour of the function pointer.
