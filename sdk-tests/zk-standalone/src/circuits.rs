use xark::prelude::*;
use zolana_circuit::poseidon;

#[input]
pub struct Note { pub amount: u64, pub blinding: Field }

#[input]
pub struct Payout {
    pub commitment: Field,
    pub amount: u64,
    pub destination_hi: Field,
    pub destination_lo: u8,
}

#[circuit]
pub fn withdrawal(private: Private<Note>, public: Public<Payout>) {
    public.destination_hi.to_bits::<248>();
    require_eq(private.amount, public.amount);
    require_eq(poseidon(&[Field::from(private.amount), private.blinding,
        public.destination_hi, Field::from(public.destination_lo)]).unwrap(), public.commitment);
}

#[cfg(not(xark))]
impl WithdrawalInputs {
    pub fn example() -> Self {
        let amount = 250;
        let blinding = Field::from(99u64);
        let destination_hi = Field::from_be_bytes(&[7u8; 31]);
        let destination_lo = 7u8;
        let commitment = poseidon(&[Field::from(amount), blinding, destination_hi, Field::from(destination_lo)]).unwrap();
        Self { private: Note { amount, blinding }, public: Payout { commitment, amount, destination_hi, destination_lo } }
    }
}

#[cfg(not(xark))]
impl Payout {
    pub fn destination(&self) -> [u8; 32] {
        let packed = zolana_circuit::to_bytes(&self.destination_hi);
        let mut out = [0u8; 32];
        out[..31].copy_from_slice(&packed[1..]); out[31] = self.destination_lo;
        out
    }
}
