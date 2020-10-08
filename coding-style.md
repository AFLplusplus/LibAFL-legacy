# How to write code in LibAFL

## Class definitions

All classes are composed of one or more C struct definitions and inheriths the common base class `afl_object`.

Consider if we want to define a class with a single integer field, the syntax is the following:

```c
struct afl_A {

  AFL_INHERITS(afl_object)
  
  int x;

};
```

Each class should define an `afl_typename_t` type like the following:

```c
typedef struct afl_A afl_A_t;
```

If we want to declare some virtual methods, we have to define the vtable structure corresponding to the class:

```c
struct afl_A_vtable {

  AFL_VTABLE_INHERITS(afl_object)

  void (*print)(afl_A_t* self);

};
```

The methods take the `self` pointer to the instance as first argument.

Each class must have a related vtable instance declared as global variable. In this case, it has the type `afl_A_vtable` because we defined a vtable type for `afl_A`, in the case in which the class does not need a vtable, the type of the vtable instance is the vtable type of the first parent class with a vtable, `afl_object_vtable` if there is not such parent class.

```c
void afl_A_deinit__nonvirtual(afl_object_t* self);

struct afl_A_vtable afl_A_vtable_instance = {
  
  // afl_object vtable
  ._base = {
  
    VTABLE_INIT_BASE_VPTR(afl_object),

    .deinit = &afl_A_deinit__nonvirtual
    
  },
  
  .print = NULL

};
```

Each vtable includes the vtables of the parent classes (`_base` field) and you have to used the nested initialization. `VTABLE_INIT_BASE_VPTR` has to be included in the `afl_object` vtable initialization and takes the name of the parent class.

As we define `afl_A` as virtual class, we do not allow the user to instantiate an object fo this class. In case that we need a contructor (`afl_typename_init`) to be called from the constructor of the derived class, we define it as protected using `__protected`. In the init, we have to set the vtable instance.

```c
// Protected init for virtual classes
void afl_A_init__protected(afl_A_t* self, int x) {

  self->x = x;
  
  AFL_VTABLE_SET(self, afl_A_vtable_instance);

}
```

For each virtual method, you have to define a static function in the header that simply wraps the virtual call. In this case we consider `afl_A` as a virtual class, we do not provide a default implementation of `print`.

```c
static inline void afl_A_print(afl_A_t* self) {
  
  AFL_VTABLEOF(afl_A, self)->print(self); 
  
}
```

When we prodive a default implementation, we use the `__nonvirtual` modifiers adding it at the end of the function name. For nonvirtuals, the self parameter has the oroginal type of the parent class that defined the virtual method (`afl_object` defines the deinit in this case). In this case too, we define a wrapper with self of the actual type of the class that simply forwards the call to the parent class.

```c
// For the nonvirtuals, maintain the original type of self (afl_object_t)
void afl_A_deinit__nonvirtual(afl_object_t* self) {
  
  if (AFL_INSTANCEOF(afl_A, self)) // do only for debug builds maybe
    AFL_DYN_CAST(afl_A, self)->x = 0;
  
}

// For the wrappers, use the actual self type (afl_A_t)
static inline void afl_A_deinit(afl_A_t* self) {
  
  afl_object_deinit(AFL_BASEOF(self));
  
}
```

### Derived classes

Consider now if we want to define a derived class of the virtual class `afl_A`, `afl_B`.

This class provides an implementation to `print` and it is not virtual, we want to allow the user to create instances so we define a public init.

The definition will be the following:

```c
void afl_B_print__nonvirtual(afl_A_t* self);

typedef struct afl_B afl_B_t;

struct afl_A_vtable afl_B_vtable_instance = {
  
  // afl_object_vtable
  ._base = {
  
    AFL_VTABLE_INIT_BASE_VPTR(afl_A), // declare the parent vtable
    
    .deinit = &afl_A_deinit__nonvirtual // reuse A deinit
  
  },

  .print = &afl_B_print__nonvirtual

};

struct afl_B {

  AFL_INHERITS(afl_A)
  
};

void afl_B_init(afl_B_t* self, int x) {

  // Call parent constructor
  afl_A_init__protected(AFL_BASEOF(self), x);
  
  VTABLE_SET(self, afl_B_vtable_instance);

}

void afl_B_print__nonvirtual(afl_A_t* self) {

  if (AFL_INSTANCEOF(afl_B, self))
    printf("B: %d\n", self->x);

}

// Forward the wrapper to afl_A
static inline void afl_B_print(afl_B_t* self) {
  
  afl_A_print(BASE_CAST(self));

}
```
