use proptest::prelude::*;

proptest! {
    #[test]
    fn test_addition(a in 0..1000000u64, b in 0..1000000u64) {
        prop_assume!(a + b >= a);
        prop_assert_eq!(a + b, b + a);
    }
}