use zolana_hasher::{primitives::right_align, Hasher, HasherError, Poseidon};

pub trait ToByteArray {
    fn to_byte_array(&self) -> Result<[u8; 32], HasherError>;
}

macro_rules! impl_to_byte_array_for_integer {
    ($($integer:ty),*) => {
        $(
            impl ToByteArray for $integer {
                fn to_byte_array(&self) -> Result<[u8; 32], HasherError> {
                    Ok(right_align(&self.to_be_bytes()))
                }
            }
        )*
    };
}

impl_to_byte_array_for_integer!(u16, u32, u64);

impl ToByteArray for bool {
    fn to_byte_array(&self) -> Result<[u8; 32], HasherError> {
        Ok(right_align(&[u8::from(*self)]))
    }
}

impl ToByteArray for [u8; 32] {
    fn to_byte_array(&self) -> Result<[u8; 32], HasherError> {
        Ok(*self)
    }
}

impl<T: ToByteArray, const N: usize> ToByteArray for [T; N] {
    fn to_byte_array(&self) -> Result<[u8; 32], HasherError> {
        let mut elements = [[0u8; 32]; N];
        for (target, element) in elements.iter_mut().zip(self.iter()) {
            *target = element.to_byte_array()?;
        }
        Poseidon::hashv(&elements.each_ref().map(<[u8; 32]>::as_slice))
    }
}
