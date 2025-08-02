use super::core::Container;
use std::sync::{Arc,Mutex,RwLock};
#[cfg(not(feature = "no-rc"))]
use std::rc::Rc;
use std::borrow::Cow;
#[cfg(not(feature = "no-rc"))]
use std::cell::RefCell;

// --- From Raw ---

// ----- Simple Variants -----
impl<T: Clone> From<(/* Empty */)>  for Container<'_, T> {fn from((): ()) -> Self {Container::Empty}}
impl<T: Clone> From<Box<[T]>> for Container<'_, T> {fn from(value: Box<[T]>) -> Self {Container::Box(value)}}
impl<T: Clone> From<Vec<T>> for Container<'_, T> {fn from(value: Vec<T>) -> Self {Container::Vec(value)}}
impl<'a, T: Clone> From<&'a [T]> for Container<'a, T> {fn from(value: &'a [T]) -> Self {Container::Ref(value)}}
impl<'a, T: Clone> From<Cow<'a, [T]>> for Container<'a, T> {fn from(value: Cow<'a, [T]>) -> Self {Container::Cow(value)}}
#[cfg(not(feature = "no-rc"))]
impl<T: Clone> From<Rc<[T]>> for Container<'_, T> {fn from(value: Rc<[T]>) -> Self {Container::Rc(value)}}
impl<T: Clone> From<Arc<[T]>> for Container<'_, T> {fn from(value: Arc<[T]>) -> Self {Container::Arc(value)}}
// ----- Compound Variants -----
impl<'a, T: Clone> From<&'a Box<[T]>> for Container<'a, T> {fn from(value: &'a Box<[T]>) -> Self {Container::RefBox(value)}}
impl<'a, T: Clone> From<&'a Vec<T>> for Container<'a, T> {fn from(value: &'a Vec<T>) -> Self {Container::RefVec(value)}}
impl<'a, T: Clone> From<Cow<'a, Box<[T]>>> for Container<'a, T> {fn from(value: Cow<'a, Box<[T]>>) -> Self {Container::CowBox(value)}}
impl<'a, T: Clone> From<Cow<'a, Vec<T>>> for Container<'a, T> {fn from(value: Cow<'a, Vec<T>>) -> Self {Container::CowVec(value)}}
#[cfg(not(feature = "no-rc"))]
impl<T: Clone> From<Rc<Box<[T]>>> for Container<'_, T> {fn from(value: Rc<Box<[T]>>) -> Self {Container::RcBox(value)}}
#[cfg(not(feature = "no-rc"))]
impl<T: Clone> From<Rc<Vec<T>>> for Container<'_, T> {fn from(value: Rc<Vec<T>>) -> Self {Container::RcVec(value)}}
impl<T: Clone> From<Arc<Box<[T]>>> for Container<'_, T> {fn from(value: Arc<Box<[T]>>) -> Self {Container::ArcBox(value)}}
impl<T: Clone> From<Arc<Vec<T>>> for Container<'_, T> {fn from(value: Arc<Vec<T>>) -> Self {Container::ArcVec(value)}}
// ----- Locking Variants -----
#[cfg(not(feature = "no-rc"))]
impl<T: Clone> From<Rc<RefCell<Box<[T]>>>> for Container<'_, T> {fn from(value: Rc<RefCell<Box<[T]>>>) -> Self {Container::RcRefCellBox(value)}}
#[cfg(not(feature = "no-rc"))]
impl<T: Clone> From<Rc<RefCell<Vec<T>>>> for Container<'_, T> {fn from(value: Rc<RefCell<Vec<T>>>) -> Self {Container::RcRefCellVec(value)}}
impl<T: Clone> From<Arc<Mutex<Box<[T]>>>> for Container<'_, T> {fn from(value: Arc<Mutex<Box<[T]>>>) -> Self {Container::ArcMutexBox(value)}}
impl<T: Clone> From<Arc<Mutex<Vec<T>>>> for Container<'_, T> {fn from(value: Arc<Mutex<Vec<T>>>) -> Self {Container::ArcMutexVec(value)}}
impl<T: Clone> From<Arc<RwLock<Box<[T]>>>> for Container<'_, T> {fn from(value: Arc<RwLock<Box<[T]>>>) -> Self {Container::ArcRwLockBox(value)}}
impl<T: Clone> From<Arc<RwLock<Vec<T>>>> for Container<'_, T> {fn from(value: Arc<RwLock<Vec<T>>>) -> Self {Container::ArcRwLockVec(value)}}


// --- Clone ---

// Clone for Container<T> where T is Clone
impl<T: Clone> Clone for Container<'_, T> {
    /// Creates a new container which wraps the same or identical underyling objects. 
    /// This method will do its best to avoid a deep copy, but some copies are unavoidable. 
    fn clone(&self) -> Self {
        match self {
            // ----- Simple Variants -----
            Container::Empty => Container::Empty,
            Container::Box(value) => Container::Box(value.clone()),
            Container::Vec(value) => Container::Vec(value.clone()),
            Container::Ref(value) => Container::Ref(value),
            Container::Cow(value) => Container::Cow(value.clone()),
            #[cfg(not(feature = "no-rc"))]
            Container::Rc(value) => Container::Rc(value.clone()),
            Container::Arc(value) => Container::Arc(value.clone()),
            // ----- Compound Variants -----
            Container::RefBox(value) => Container::RefBox(value),
            Container::RefVec(value) => Container::RefVec(value),
            Container::CowBox(value) => Container::CowBox(value.clone()),
            Container::CowVec(value) => Container::CowVec(value.clone()),
            #[cfg(not(feature = "no-rc"))]
            Container::RcBox(value) => Container::RcBox(value.clone()),
            #[cfg(not(feature = "no-rc"))]
            Container::RcVec(value) => Container::RcVec(value.clone()),
            Container::ArcBox(value) => Container::ArcBox(value.clone()),
            Container::ArcVec(value) => Container::ArcVec(value.clone()),
            // ----- Locking Variants -----
            #[cfg(not(feature = "no-rc"))]
            Container::RcRefCellBox(value) => Container::RcRefCellBox(value.clone()),
            #[cfg(not(feature = "no-rc"))]
            Container::RcRefCellVec(value) => Container::RcRefCellVec(value.clone()),
            Container::ArcMutexBox(value) => Container::ArcMutexBox(value.clone()),
            Container::ArcMutexVec(value) => Container::ArcMutexVec(value.clone()),
            Container::ArcRwLockBox(value) => Container::ArcRwLockBox(value.clone()),
            Container::ArcRwLockVec(value) => Container::ArcRwLockVec(value.clone()),
        }
    }
}

// --- Additional utility methods ---

impl<T: Clone> Container<'_, T> {
    /// Returns the length of the container.
    /// Returns zero if the source data is unavailable.
    #[must_use]
    pub fn len(&self) -> usize {
        match self.try_borrow(){
            Ok(value) => value.len(),
            Err(_)=>0,
        }
    }

    /// Returns true if the container is empty.
    /// Also returns true if the source data is unavailable. 
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Converts the container to an owned `Vec<T>`.
    /// This will most likely be a copy.
    /// Returns an empty vector if the source data is unavailable.
    #[must_use]
    pub fn to_vec(&self) -> Vec<T> {
        match self.try_borrow(){
            Ok(value) => value.to_vec(),
            Err(_)=>Vec::new(),
        }
    }
}

// ----- Serialize -----
#[cfg(feature = "serializable")]
mod serialize {
    use super::Container;
    use super::super::core::Borrow;
    use serde::{Deserialize, Deserializer, Serialize, Serializer, ser::SerializeSeq};
    /// Serialize a Borrow. 
    impl<T: Serialize + Clone> Serialize for Borrow<'_, T> {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: Serializer {
                let mut seq = serializer.serialize_seq(Some(self.len()))?;
                for e in self.as_ref() {
                    seq.serialize_element(e)?;
                }
                seq.end()    
        }
    }
    /// Serialize a Container by borrowing.
    /// Writes nothing if the borrow fails.
    impl<T: Serialize + Clone> Serialize for Container<'_, T> {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: Serializer {
                let borrow = self.try_borrow().unwrap_or(Borrow::Empty);
                let mut seq = serializer.serialize_seq(Some(borrow.len()))?;
                for e in borrow.as_ref() {
                    seq.serialize_element(e)?;
                }
                seq.end()    
        }
    }
    /// Deserialize into a Container.
    impl<'de, T: Deserialize<'de> + Clone> Deserialize<'de> for Container<'_, T> {
        fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
            let v = Vec::<T>::deserialize(d)?;
            Ok(Container::Vec(v))
        }
    }
}