// This file contains unit tests for the Container enum
// and its trait implementations.
#![allow(clippy::match_wild_err_arm)] // any error fails the test

use crate::container::Container;
use std::sync::Arc;
#[cfg(not(feature = "no-rc"))]
use std::rc::Rc;

#[cfg(test)]
mod u8 {
    use super::*;

    #[test]
    fn container_clone_slice() {
        let data_vec: Vec<u8> = vec![1, 2, 3];
        let container1: Container<'_, u8> = Container::from(data_vec.clone()); // This will be Container::Vec
        let container2 = container1.clone();
        assert_eq!(&*container1.borrow(), &*container2.borrow());
        match (&container1, &container2) {
            (Container::Vec(v1), Container::Vec(v2)) => { // Expect Vec after cloning Vec
                assert_ne!(v1.as_ptr(), v2.as_ptr(), "Cloned Vec<u8> should have different pointers");
            }
            _ => panic!("Expected Vec variants for Container::from(Vec<u8>) clone"),
        }

        let borrowed_slice: &[u8] = &[4,5,6];
        let c_borrowed1 : Container<'_, u8> = Container::Ref(borrowed_slice);
        let c_borrowed2 = c_borrowed1.clone();
        assert_eq!(*c_borrowed1.borrow(), *c_borrowed2.borrow());
        assert_eq!((*c_borrowed1.borrow()).as_ptr(), (*c_borrowed2.borrow()).as_ptr());

        let shared_slice_arc: Arc<[u8]> = Arc::new([7,8,9]);
        let c_shared1 : Container<'_, u8> = Container::Arc(shared_slice_arc.clone());
        let c_shared2 = c_shared1.clone();
        if let Container::Arc(s2_arc) = &c_shared2 {
            assert!(Arc::ptr_eq(s2_arc, &shared_slice_arc));
        } else { panic!("Expected shared after clone"); }
    }

    #[test]
    fn container_deref_slice() {
        let data: &[u8] = &[1, 2, 3, 4, 5];
        let container: Container<'_, u8> = Container::from(data);
        let borrowed = container.borrow();
        assert_eq!(borrowed.len(), 5); // Test Deref to [u8]
        assert_eq!(borrowed[0], 1);
    }

    #[test]
    fn borrowed_variants() {
        let data_slice: &'static [u8] = &[1, 2, 3];
        let data_box: Box<[u8]> = Box::new([4, 5, 6]);
        let data_vec: Vec<u8> = vec![7, 8, 9];

        // Container::Ref
        let container_ref = Container::Ref(data_slice);
        assert_eq!(&*container_ref.borrow(), data_slice);

        // Container::Cow (borrowed)
        let container_cow_borrowed = Container::Cow(std::borrow::Cow::Borrowed(data_slice));
        assert_eq!(&*container_cow_borrowed.borrow(), data_slice);

        // Container::RefBox
        let container_ref_box = Container::RefBox(&data_box);
        assert_eq!(&*container_ref_box.borrow(), data_box.as_ref());

        // Container::RefVec
        let container_ref_vec = Container::RefVec(&data_vec);
        assert_eq!(&*container_ref_vec.borrow(), data_vec.as_slice());

        // Container::CowBox (borrowed)
        let container_cow_box_borrowed = Container::CowBox(std::borrow::Cow::Borrowed(&data_box));
        assert_eq!(&*container_cow_box_borrowed.borrow(), data_box.as_ref());

        // Container::CowVec (borrowed)
        let container_cow_vec_borrowed = Container::CowVec(std::borrow::Cow::Borrowed(&data_vec));
        assert_eq!(&*container_cow_vec_borrowed.borrow(), data_vec.as_slice());
    }

    #[test]
    fn owned_variants() {
        let data_box_orig: Box<[u8]> = Box::new([1, 2, 3]);
        let data_vec_orig: Vec<u8> = vec![4, 5, 6];
        let data_arc_orig: Arc<[u8]> = Arc::new([10, 11, 12]);

        // Container::Box
        let container_box = Container::from(data_box_orig.clone());
        assert_eq!(&*container_box.borrow(), data_box_orig.as_ref());

        // Container::Vec
        let container_vec = Container::from(data_vec_orig.clone());
        assert_eq!(&*container_vec.borrow(), data_vec_orig.as_slice());

        // Container::Cow (owned from Vec)
        let container_cow_owned_vec = Container::Cow(std::borrow::Cow::Owned(data_vec_orig.clone()));
        assert_eq!(&*container_cow_owned_vec.borrow(), data_vec_orig.as_slice());

        // Container::Cow (owned from Box) - Note: Cow doesn't directly take Box<[T]>, so we convert to Vec<T> first for owned Cow
        let container_cow_owned_box_as_vec = Container::Cow(std::borrow::Cow::Owned(data_box_orig.to_vec()));
        assert_eq!(&*container_cow_owned_box_as_vec.borrow(), data_box_orig.as_ref());

        #[cfg(not(feature = "no-rc"))]
        {
            // Container::Rc
            let data_rc_orig: Rc<[u8]> = Rc::new([7, 8, 9]);
            let container_rc = Container::from(data_rc_orig.clone());
            assert_eq!(&*container_rc.borrow(), data_rc_orig.as_ref());
        }

        // Container::Arc
        let container_arc = Container::from(data_arc_orig.clone());
        assert_eq!(&*container_arc.borrow(), data_arc_orig.as_ref());

        #[cfg(not(feature = "no-rc"))]
        {
            // Container::RcBox
            let container_rc_box = Container::RcBox(Rc::new(data_box_orig.clone()));
            assert_eq!(&*container_rc_box.borrow(), data_box_orig.as_ref());

            // Container::RcVec
            let container_rc_vec = Container::RcVec(Rc::new(data_vec_orig.clone()));
            assert_eq!(&*container_rc_vec.borrow(), data_vec_orig.as_slice());
        }

        // Container::ArcBox
        let container_arc_box = Container::ArcBox(Arc::new(data_box_orig.clone()));
        assert_eq!(&*container_arc_box.borrow(), data_box_orig.as_ref());

        // Container::ArcVec
        let container_arc_vec = Container::ArcVec(Arc::new(data_vec_orig.clone()));
        assert_eq!(&*container_arc_vec.borrow(), data_vec_orig.as_slice());
    }

    #[test]
    fn locking_variants_read() {
        let data_box_orig: Box<[u8]> = Box::new([1, 2, 3]);
        let data_vec_orig: Vec<u8> = vec![4, 5, 6];
        
        #[cfg(not(feature = "no-rc"))]
        {
            // Container::RcRefCellBox
            let rc_ref_cell_box = Rc::new(std::cell::RefCell::new(data_box_orig.clone()));
            let container_rc_ref_cell_box: Container<'static, u8> = Container::from(rc_ref_cell_box.clone());
            match container_rc_ref_cell_box.try_borrow() {
                Ok(guard) => assert_eq!(&*guard, data_box_orig.as_ref()),
                Err(_) => panic!("Expected Ok for RcRefCellBox get_slice"),
            }

            // Container::RcRefCellVec
            let rc_ref_cell_vec = Rc::new(std::cell::RefCell::new(data_vec_orig.clone()));
            let container_rc_ref_cell_vec: Container<'static, u8> = Container::from(rc_ref_cell_vec.clone());
            match container_rc_ref_cell_vec.try_borrow() {
                Ok(guard) => assert_eq!(&*guard, data_vec_orig.as_slice()),
                Err(_) => panic!("Expected Ok for RcRefCellVec get_slice"),
            }; // this weird semicolon is needed because of lifetimes
        }

        // Container::ArcMutexBox
        let arc_mutex_box = Arc::new(std::sync::Mutex::new(data_box_orig.clone()));
        let container_arc_mutex_box: Container<'static, u8> = Container::from(arc_mutex_box.clone());
        match container_arc_mutex_box.try_borrow() {
            Ok(guard) => assert_eq!(&*guard, data_box_orig.as_ref()),
            Err(_) => panic!("Expected Ok for ArcMutexBox get_slice"),
        }

        // Container::ArcMutexVec
        let arc_mutex_vec = Arc::new(std::sync::Mutex::new(data_vec_orig.clone()));
        let container_arc_mutex_vec: Container<'static, u8> = Container::from(arc_mutex_vec.clone());
        match container_arc_mutex_vec.try_borrow() {
            Ok(guard) => assert_eq!(&*guard, data_vec_orig.as_slice()),
            Err(_) => panic!("Expected Ok for ArcMutexVec get_slice"),
        }

        // Container::ArcRwLockBox
        let arc_rw_lock_box = Arc::new(std::sync::RwLock::new(data_box_orig.clone()));
        let container_arc_rw_lock_box: Container<'static, u8> = Container::from(arc_rw_lock_box.clone());
        match container_arc_rw_lock_box.try_borrow() {
            Ok(guard) => assert_eq!(&*guard, data_box_orig.as_ref()),
            Err(_) => panic!("Expected Ok for ArcRwLockBox get_slice"),
        }

        // Container::ArcRwLockVec
        let arc_rw_lock_vec = Arc::new(std::sync::RwLock::new(data_vec_orig.clone()));
        let container_arc_rw_lock_vec: Container<'static, u8> = Container::from(arc_rw_lock_vec.clone());
        match container_arc_rw_lock_vec.try_borrow() {
            Ok(guard) => assert_eq!(&*guard, data_vec_orig.as_slice()),
            Err(_) => panic!("Expected Ok for ArcRwLockVec get_slice"),
        };
    }

    #[test]
    fn locking_variants_try_as_ref_error() {
        let data_box_orig: Box<[u8]> = Box::new([1, 2, 3]);
        let data_vec_orig: Vec<u8> = vec![4, 5, 6];

        #[cfg(not(feature = "no-rc"))]
        {
            // Container::RcRefCellBox
            let rc_ref_cell_box = Rc::new(std::cell::RefCell::new(data_box_orig.clone()));
            let container_rc_ref_cell_box: Container<'static, u8> = Container::from(rc_ref_cell_box);
            assert!(container_rc_ref_cell_box.try_as_ref().is_err());

            // Container::RcRefCellVec
            let rc_ref_cell_vec = Rc::new(std::cell::RefCell::new(data_vec_orig.clone()));
            let container_rc_ref_cell_vec: Container<'static, u8> = Container::from(rc_ref_cell_vec);
            assert!(container_rc_ref_cell_vec.try_as_ref().is_err());
        }

        // Container::ArcMutexBox
        let arc_mutex_box = Arc::new(std::sync::Mutex::new(data_box_orig.clone()));
        let container_arc_mutex_box: Container<'static, u8> = Container::from(arc_mutex_box);
        assert!(container_arc_mutex_box.try_as_ref().is_err());

        // Container::ArcMutexVec
        let arc_mutex_vec = Arc::new(std::sync::Mutex::new(data_vec_orig.clone()));
        let container_arc_mutex_vec: Container<'static, u8> = Container::from(arc_mutex_vec);
        assert!(container_arc_mutex_vec.try_as_ref().is_err());

        // Container::ArcRwLockBox
        let arc_rw_lock_box = Arc::new(std::sync::RwLock::new(data_box_orig.clone()));
        let container_arc_rw_lock_box: Container<'static, u8> = Container::from(arc_rw_lock_box);
        assert!(container_arc_rw_lock_box.try_as_ref().is_err());

        // Container::ArcRwLockVec
        let arc_rw_lock_vec = Arc::new(std::sync::RwLock::new(data_vec_orig.clone()));
        let container_arc_rw_lock_vec: Container<'static, u8> = Container::from(arc_rw_lock_vec);
        assert!(container_arc_rw_lock_vec.try_as_ref().is_err());
    }

    #[test]
    fn as_ref() {
        let data: &[u8] = &[1, 2, 3, 4, 5];
        let container: Container<'_, u8> = Container::from(data);
        assert_eq!(container.as_ref(), data);
    }
}

#[cfg(test)]
mod string {
    use crate::container::Container;
    #[cfg(unix)]
    use std::os::unix::ffi::OsStrExt;
    use std::ffi::{OsStr, OsString};
    use std::sync::{Arc, Mutex, RwLock};
    #[cfg(not(feature = "no-rc"))]
    use std::cell::RefCell;
    #[cfg(not(feature = "no-rc"))]
    use std::rc::Rc;
    use std::borrow::Cow;

    // --- Test Data ---
    const VALID_UTF8_STR: &str = "hello world";
    const VALID_UTF8_BYTES: &[u8] = b"hello world";
    // Invalid UTF-8 sequence (from Rust docs for from_utf8)
    const INVALID_UTF8_BYTES: &[u8] = &[0xf0, 0x90, 0x80];


    // --- Tests for From<String/&str> ---
    #[test]
    fn from_string_etc_for_container_u8() {
        let s = String::from(VALID_UTF8_STR);
        let container: Container<'_, u8> = Container::from(s.clone());
        assert_eq!(&*container.borrow(), s.as_bytes());
        match container {
            Container::Vec(_) => {} // Expected
            _ => panic!("Expected Container::Vec from String"),
        }
   
        let s_ref: &str = VALID_UTF8_STR;
        let container: Container<'_, u8> = Container::from(s_ref);
        assert_eq!(&*container.borrow(), s_ref.as_bytes());
        match container {
            Container::Ref(_) => {} // Expected
            _ => panic!("Expected Container::Ref from &str"),
        }

        let os_string = OsString::from(VALID_UTF8_STR);
        let container: Container<'_, u8> = Container::from(os_string.clone());
        assert_eq!(&*container.borrow(), OsStr::new(VALID_UTF8_STR).as_bytes());
         match container {
            Container::Vec(_) => {} // Expected
            _ => panic!("Expected Container::Vec from OsString"),
        }

        let os_str_ref = OsStr::new(VALID_UTF8_STR);
        let container: Container<'_, u8> = Container::from(os_str_ref);
        assert_eq!(&*container.borrow(), os_str_ref.as_bytes());
        match container {
            Container::Ref(_) => {} // Expected
            _ => panic!("Expected Container::Ref from &OsStr"),
        }
    }

    // --- Helper to create containers for testing ---
    fn create_non_locking_containers(bytes: &[u8]) -> Vec<Container<'_, u8>> {
        vec![
            Container::Ref(bytes),
            Container::Vec(bytes.to_vec()),
            Container::Box(bytes.to_vec().into_boxed_slice()),
            Container::Cow(Cow::Borrowed(bytes)),
            Container::Cow(Cow::Owned(bytes.to_vec())),
            Container::Arc(Arc::from(bytes)),
            #[cfg(not(feature = "no-rc"))]
            Container::Rc(Rc::from(bytes)),
        ]
    }

    fn create_locking_containers(bytes: &[u8]) -> Vec<Container<'_, u8>> {
        vec![
            Container::ArcMutexVec(Arc::new(Mutex::new(bytes.to_vec()))),
            Container::ArcRwLockVec(Arc::new(RwLock::new(bytes.to_vec()))),
            #[cfg(not(feature = "no-rc"))]
            Container::RcRefCellVec(Rc::new(RefCell::new(bytes.to_vec()))),
        ]
    }


    #[test]
    fn to_str_etc() {
        // Valid UTF-8
        for container in create_non_locking_containers(VALID_UTF8_BYTES) {
            assert_eq!(container.try_to_string().unwrap(), VALID_UTF8_STR);
        }
        for container in create_locking_containers(VALID_UTF8_BYTES) {
            assert_eq!(container.try_to_string().unwrap(), VALID_UTF8_STR);
        }
        // Invalid UTF-8
        for container in create_non_locking_containers(INVALID_UTF8_BYTES) {
            assert!(container.try_to_string().is_err());
        }
        for container in create_locking_containers(INVALID_UTF8_BYTES) {
            assert!(container.try_to_string().is_err());
        }

        // Valid Os bytes
        for container in create_non_locking_containers(VALID_UTF8_BYTES) {
            assert_eq!(container.try_to_os_string().unwrap(), OsString::from(VALID_UTF8_STR));
        }
        for container in create_locking_containers(VALID_UTF8_BYTES) {
            assert_eq!(container.try_to_os_string().unwrap(), OsString::from(VALID_UTF8_STR));
        }
    }
}
