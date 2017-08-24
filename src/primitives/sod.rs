/// Sod stands for Static or Dynamic. An enum to encapsulate values which
/// are either dynamically, heap-allocated values, or statics.
///
/// This allows us to define default primitives which are used throughout
/// without the overhead of reference counting, while still supporting the
/// flexibility to create primitives dynamically.
/// 
/// Thanks to the `Deref` implementation, either variants are treated like
/// the inner type without needing to worry about which it is.
///
/// Many thanks to [panicbit](https://github.com/panicbit) for helping to
/// get the `Deref` implementation working to make all the magic happen. 

use std::sync::Arc;
use std::ops::Deref;

#[derive(PartialEq, PartialOrd)]
/// Enum to hold either static references or reference-counted owned objects.
/// Implements `Deref` to `T` for ease of use.
/// Since internal data is either a static reference, or an `Arc`, cloning
/// is a cheap operation.
pub enum Sod<T: ?Sized + 'static> {
    /// Static reference to T
    Static(&'static T),
    /// Dynamically allocated T, on the heap, atomically reference-counted.
    Dynamic(Arc<Box<T>>),
}

impl<T: ?Sized> Deref for Sod<T> {
    type Target = T;
    fn deref(&self) -> &T {
        match *self {
            Sod::Static(t) => t,
            Sod::Dynamic(ref t) => t,
        }
    }
}

impl<T: ?Sized> Clone for Sod<T> {
    fn clone(&self) -> Sod<T> {
        match *self {
            Sod::Static(t) => Sod::Static(t),
            Sod::Dynamic(ref t) => Sod::Dynamic(t.clone())
        }
    }
}
