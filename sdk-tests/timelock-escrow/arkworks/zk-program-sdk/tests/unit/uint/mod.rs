mod arithmetic;
mod construction;
mod conversions;
mod picus_form;
mod relations;
mod rows;

/// One check at a `Uint` width, run by [`at_widths!`] at each pinned width.
pub trait Widths {
    type Output;

    fn at<const BITS: u32>(&self) -> Self::Output;
}

/// `[(bits, widths.at::<bits>()), ...]`; a macro, so only the listed widths
/// are instantiated and a width a method refuses at compile time is never
/// reached.
macro_rules! at_widths {
    ($widths:expr, [$($bits:literal),+ $(,)?]) => {
        vec![$(($bits, $crate::uint::Widths::at::<$bits>($widths))),+]
    };
}

pub(crate) use at_widths;
