use std::sync::{Arc,Mutex,RwLock};
#[cfg(not(feature = "no-rc"))]
use std::rc::Rc;
use std::borrow::Cow;
#[cfg(not(feature = "no-rc"))]
use std::cell::{Ref, RefCell};
use std::ops::Deref;
use std::sync::{MutexGuard, RwLockReadGuard, PoisonError};

#[derive(Debug)]
/// A generic container enum that provides flexible ownership models for unsized data types.
/// If there is a borrow, its lifetime is 'a (most likely 'static).
pub enum Container<'a, T: Clone> {
    // ----- Simple Variants -----
    /// No data.
    Empty,
    /// An owned, fixed-size, heap-allocated slice.
    Box(Box<[T]>),
    /// An owned, growable, heap-allocated vector.
    Vec(Vec<T>),
    /// A borrowed slice.
    Ref(&'a [T]),
    /// A borrowed slice with copy-on-write.
    Cow(Cow<'a, [T]>),
    #[cfg(not(feature = "no-rc"))]
    /// A reusable, fixed-size slice.
    Rc(Rc<[T]>),
    /// A shared, fixed-size slice.
    Arc(Arc<[T]>),
    // ----- Compount Variants -----
    #[allow(clippy::borrowed_box)]
    /// A borrowed, fixed-size, heap-allocated slice.
    RefBox(&'a Box<[T]>),
    /// A borrowed, immutable, heap-allocated vector. 
    RefVec(&'a Vec<T>),
    /// A borrowed, fixed-size, heap-allocated vector, with copy-on-write. 
    CowBox(Cow<'a, Box<[T]>>),
    /// A borrowed, immutable, heap-allocated vactor, with copy-on-write.
    CowVec(Cow<'a, Vec<T>>),
    #[cfg(not(feature = "no-rc"))]
    /// A reusable, fixed-size, heap-allocated slice.
    RcBox(Rc<Box<[T]>>),
    #[cfg(not(feature = "no-rc"))]
    /// A reusable, immutable, heap-allocated vector.
    RcVec(Rc<Vec<T>>),
    /// A shared, fixed-size, heap-allocated slice.
    ArcBox(Arc<Box<[T]>>),
    /// A shared, immutable, heap-allocated vector.
    ArcVec(Arc<Vec<T>>),
    // ----- Locking Variants -----
    #[cfg(not(feature = "no-rc"))]
    /// A reusable, replaceable, heap-allocated slice.
    RcRefCellBox(Rc<RefCell<Box<[T]>>>),
    #[cfg(not(feature = "no-rc"))]
    /// A reusable, growable, heap-allocated vector.
    RcRefCellVec(Rc<RefCell<Vec<T>>>),
    /// A shared, fixed-size, replacable, heap-allocated slice.
    ArcMutexBox(Arc<Mutex<Box<[T]>>>),
    /// A shared, growable, heap-allocated vector.
    ArcMutexVec(Arc<Mutex<Vec<T>>>),
    /// A shared, fixed-size, replacable, heap-allocated slide with multiple readers.
    ArcRwLockBox(Arc<RwLock<Box<[T]>>>),
    /// A shared, growable, heap-allocated vector with multiple readers.
    ArcRwLockVec(Arc<RwLock<Vec<T>>>),
}

// ----- Borrow from a Container -----

#[derive(Debug)]
/// A value borrowed from a container with flexible ownership models for unsized data types.
pub enum Borrow<'a, T> {
    // ----- Simple Variants -----
    /// No data.
    Empty,
    /// A borrowed reference to a slice.
    Slice(&'a [T]),
    // ----- Locking Variants -----
    #[cfg(not(feature = "no-rc"))]
    /// A borrowed reference to a reusable, replaceable, heap-allocated slice.
    RcRefCellBox(Ref<'a, Box<[T]>>),
    #[cfg(not(feature = "no-rc"))]
    /// A borrowed reference to a reusable, growable, heap-allocated vector.
    RcRefCellVec(Ref<'a, Vec<T>>),
    /// A borrowed reference to a shared, fixed-size, replacable, heap-allocated slice.
    ArcMutexBox(MutexGuard<'a, Box<[T]>>),
    /// A borrowed reference to a shared, growable, heap-allocated vector.
    ArcMutexVec(MutexGuard<'a, Vec<T>>),
    /// A borrowed reference to a shared, fixed-size, replacable, heap-allocated slide with multiple readers.
    ArcRwLockBox(RwLockReadGuard<'a, Box<[T]>>),
    /// A borrowed reference to a shared, growable, heap-allocated vector with multiple readers.
    ArcRwLockVec(RwLockReadGuard<'a, Vec<T>>),
}

impl<T: Clone> Deref for Borrow<'_, T> {
    type Target = [T];

    fn deref(&self) -> &Self::Target {
        match self {
            Borrow::Empty => &[],
            Borrow::Slice(value) => value,
            #[cfg(not(feature = "no-rc"))]
            Borrow::RcRefCellBox(value) => value,
            #[cfg(not(feature = "no-rc"))]
            Borrow::RcRefCellVec(value) => value,
            Borrow::ArcMutexBox(value) => value,
            Borrow::ArcMutexVec(value) => value,
            Borrow::ArcRwLockBox(value) => value,
            Borrow::ArcRwLockVec(value) => value,
        }
    }
}

// --- Container to Borrow ---
// --- Container to Reference ---

#[derive(Debug, PartialEq)]
pub enum BorrowError {
    Poisoned,
}

impl<T> From<PoisonError<T>> for BorrowError {
    fn from(_: PoisonError<T>) -> Self {
        BorrowError::Poisoned
    }
}

impl<T: Clone> Container<'_, T> {
    /// Borrows a slice-like immutable reference from the container.
    /// Will attempt to gain access to a locking variant.
    /// # Errors
    /// Returns an error if the source data is unavailable.
    pub fn try_borrow(&self) -> Result<Borrow<'_, T>, BorrowError> {
        match self {
            // ----- Simple Variants -----
            Container::Empty => Ok(Borrow::Empty),
            Container::Box(value) => Ok(Borrow::Slice(value.as_ref())),
            Container::Vec(value) => Ok(Borrow::Slice(value.as_ref())),
            Container::Ref(value) => Ok(Borrow::Slice(value)),
            Container::Cow(value) => Ok(Borrow::Slice(value.as_ref())),
            #[cfg(not(feature = "no-rc"))]
            Container::Rc(value) => Ok(Borrow::Slice(value.as_ref())),
            Container::Arc(value) => Ok(Borrow::Slice(value.as_ref())),
            // ----- Compound Variants -----
            Container::RefBox(value) => Ok(Borrow::Slice(value.as_ref())),
            Container::RefVec(value) => Ok(Borrow::Slice(value.as_ref())),
            Container::CowBox(value) => Ok(Borrow::Slice(value.as_ref().as_ref())),
            Container::CowVec(value) => Ok(Borrow::Slice(value.as_ref().as_ref())),
            #[cfg(not(feature = "no-rc"))]
            Container::RcBox(value) => Ok(Borrow::Slice(value.as_ref().as_ref())),
            #[cfg(not(feature = "no-rc"))]
            Container::RcVec(value) => Ok(Borrow::Slice(value.as_ref().as_ref())),
            Container::ArcBox(value) => Ok(Borrow::Slice(value.as_ref().as_ref())),
            Container::ArcVec(value) => Ok(Borrow::Slice(value.as_ref().as_ref())),
            // ----- Locking Variants -----
            #[cfg(not(feature = "no-rc"))]
            Container::RcRefCellBox(value) => Ok(Borrow::RcRefCellBox(value.borrow())),
            #[cfg(not(feature = "no-rc"))]
            Container::RcRefCellVec(value) => Ok(Borrow::RcRefCellVec(value.borrow())),
            Container::ArcMutexBox(value) => Ok(Borrow::ArcMutexBox(value.lock()?)),
            Container::ArcMutexVec(value) => Ok(Borrow::ArcMutexVec(value.lock()?)),
            Container::ArcRwLockBox(value) => Ok(Borrow::ArcRwLockBox(value.read()?)),
            Container::ArcRwLockVec(value) => Ok(Borrow::ArcRwLockVec(value.read()?)),
        }
    }

    /// Borrows a slice-like immutable reference from the container.
    /// Will attempt to gain access to a locking variant.
    /// # Panics
    /// Panics if the source data is unavailable.
    #[must_use]
    pub fn borrow(&self) -> Borrow<'_, T> {
        self.try_borrow().unwrap()
    }

    /// Returns a borrowed slice &[] from the container if it is an immutable variant.
    /// # Errors
    /// Returns an error if the container is a locking variant.
    /// Hint: use `try_borrow()` to handle locking variants. 
    pub fn try_as_ref(&self) -> Result<&[T], &str> {
        match self {
            // ----- Simple Variants -----
            Container::Empty => Ok(&[]), // the 'static zero-length slice of type T
            Container::Box(value) => Ok(value.as_ref()),
            Container::Vec(value) => Ok(value.as_ref()),
            Container::Ref(value) => Ok(value),
            Container::Cow(value) => Ok(value.as_ref()),
            #[cfg(not(feature = "no-rc"))]
            Container::Rc(value) => Ok(value.as_ref()),
            Container::Arc(value) => Ok(value.as_ref()),
            // ----- Compound Variants -----
            Container::RefBox(value) => Ok(value.as_ref()),
            Container::RefVec(value) => Ok(value.as_ref()),
            Container::CowBox(value) => Ok(value.as_ref().as_ref()),
            Container::CowVec(value) => Ok(value.as_ref().as_ref()),
            #[cfg(not(feature = "no-rc"))]
            Container::RcBox(value) => Ok(value.as_ref().as_ref()),
            #[cfg(not(feature = "no-rc"))]
            Container::RcVec(value) => Ok(value.as_ref().as_ref()),
            Container::ArcBox(value) => Ok(value.as_ref().as_ref()),
            Container::ArcVec(value) => Ok(value.as_ref().as_ref()),
            // ----- Locking Variants -----
            _ => Err("Attempted to get a reference from a locking container without a lock."),
        }
    }
}

impl<T: Clone> AsRef<[T]> for Container<'_, T> {
    /// Returns a borrowed slice &[] from the container.
    /// # Panics
    /// Will panic if the container is a locking variant.
    /// Hint: use `borrow()` to handle locking variants. 
    fn as_ref(&self) -> &[T] {
        self.try_as_ref().unwrap()
    }
}