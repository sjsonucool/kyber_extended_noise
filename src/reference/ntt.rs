use crate::params::{KYBER_N, KYBER_Q};
use crate::reduce::{add_mod, montgomery_reduce, sub_mod};

// Layer-order zetas in Montgomery domain, centered, regenerated for q=18446744073709550593
const ZETAS: [i128; 128] = [
    1023i128,
    6508331782171710583i128,
    -4915060868132113031i128,
    -1648873398218732860i128,
    1956284858627994667i128,
    4980019215394332423i128,
    494103389818792113i128,
    340860720427964595i128,
    5547353679562338320i128,
    5536335438024696874i128,
    1655067350488378293i128,
    6599945146724641454i128,
    2167983134046189753i128,
    6701657014995509444i128,
    5559394348411406971i128,
    -896720633044865191i128,
    7796819415381480251i128,
    5458535485254091082i128,
    -7721055463191860608i128,
    -7298575935621353811i128,
    5033092174734904030i128,
    -5931071676974415243i128,
    -6590814520403984597i128,
    -2571656260620408700i128,
    7215103830062002829i128,
    5398880675698737776i128,
    9015191346719251656i128,
    -1578784532804346894i128,
    -5503304422308823866i128,
    8528051884303949492i128,
    1650997537168724655i128,
    5019751447335360697i128,
    4425129551300165691i128,
    -1660652516864339337i128,
    -2843112392039560125i128,
    5543924236515558042i128,
    -9102660571395962579i128,
    -4952969921431234393i128,
    -7293684938959285821i128,
    8605956884467003398i128,
    139175163296689283i128,
    -6619209235949795603i128,
    -1856992747451128372i128,
    3748638733696275637i128,
    -6161756805067817074i128,
    4739267558632598752i128,
    -7717931406550811274i128,
    1302496676633627574i128,
    7756523467766583270i128,
    -1982876178303546581i128,
    -3552436274620986970i128,
    692874723358507025i128,
    6372794014681556376i128,
    -4717589276678582580i128,
    3873711764470775744i128,
    -328686832299638538i128,
    -906525486251795721i128,
    -2148829803950544185i128,
    -7059912138856529722i128,
    -7929277960392842603i128,
    58662143145854727i128,
    -2989673045846137811i128,
    2242953547947286212i128,
    1711647467859999395i128,
    -5623208453883640804i128,
    -4640056428219792130i128,
    5879847461985540262i128,
    -6929667849374472801i128,
    9192737646604094443i128,
    -7844730417247252358i128,
    708933547100965214i128,
    1329605799531535741i128,
    7100324883215819383i128,
    -4924944647778328002i128,
    -8820327757711015821i128,
    -6827761161137729892i128,
    5387949911787926312i128,
    726909394253209237i128,
    4568208395562229991i128,
    7292469776778561966i128,
    -2187062597886275514i128,
    8420283482657946382i128,
    3722352881368880604i128,
    1055675303284909590i128,
    -8003167584768640996i128,
    3588789668036177607i128,
    3694926621588991423i128,
    -6359008828140622450i128,
    -5959371165836416313i128,
    -2994945569978588337i128,
    -7290569379199440371i128,
    7256836385897082367i128,
    4604170680613276863i128,
    -7836485648400590981i128,
    2770475245391631290i128,
    -6670787170928281243i128,
    9215446063023830106i128,
    1017953543683095490i128,
    3545133518686459618i128,
    -778417046634508634i128,
    -3490210061671529602i128,
    -1185890060284655382i128,
    -3960708818405594899i128,
    3821732251781245858i128,
    3258585014627226265i128,
    6060180241057418212i128,
    -3209426151765694205i128,
    5040244760153464172i128,
    -3988252607893606831i128,
    -6699894048465176527i128,
    7705833430115172372i128,
    2761013392159648734i128,
    -2628534240961298925i128,
    -7152811098032568117i128,
    -4537593234322020172i128,
    -985556218670026389i128,
    -8729999347942500990i128,
    -2091087967287905152i128,
    2147987762353360456i128,
    -6819948190254673152i128,
    2685770627408555334i128,
    9199335061361144914i128,
    8666489809754958848i128,
    5732909017514120234i128,
    -7476262752141311223i128,
    -4347917905770761574i128,
    8150526233920562843i128,
    -141024569335178294i128,
];

// Final inverse scaling for this parameter set (Montgomery domain).
const INV_SCALE: u64 = 144115188075855872u64;
const Q: u64 = KYBER_Q as u64;

#[inline]
pub(crate) fn fqmul(a: u64, b: u64) -> u64 {
    debug_assert!(a < Q);
    debug_assert!(b < Q);
    montgomery_reduce((a as u128).wrapping_mul(b as u128))
}

#[inline]
pub(crate) fn zeta_at(i: usize) -> u64 {
    let z = ZETAS[i];
    if z < 0 {
        (z + Q as i128) as u64
    } else {
        z as u64
    }
}

#[inline]
pub fn ntt(r: &mut [u64]) {
    // In Kyber's layer ordering, zetas[0] (which equals MONT) is skipped; the
    // first stage starts with zetas[1].
    let mut k = 1usize;
    let mut len = KYBER_N / 2; // 128
    while len >= 2 {
        for start in (0..KYBER_N).step_by(2 * len) {
            let zeta = zeta_at(k);
            k += 1;
            for j in start..start + len {
                let t = fqmul(zeta, r[j + len]);
                r[j + len] = sub_mod(r[j], t);
                r[j] = add_mod(r[j], t);
            }
        }
        len >>= 1;
    }
}

pub fn invntt(r: &mut [u64]) {
    invntt_butterfly(r);
    for v in r.iter_mut() {
        *v = fqmul(*v, INV_SCALE);
    }
}

fn invntt_butterfly(r: &mut [u64]) {
    let mut k = 127usize;
    let mut len = 2usize;
    while len <= KYBER_N / 2 {
        for start in (0..KYBER_N).step_by(2 * len) {
            let zeta = zeta_at(k);
            k -= 1;
            for j in start..start + len {
                let t = r[j];
                r[j] = add_mod(t, r[j + len]);
                r[j + len] = sub_mod(r[j + len], t);
                r[j + len] = fqmul(zeta, r[j + len]);
            }
        }
        len <<= 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::params::KYBER_Q;
    use rand::{rngs::StdRng, Rng, SeedableRng};

    const R: u128 = 1u128 << 64;

    fn to_mont(x: u64) -> u64 {
        let r_mod_q = R % KYBER_Q as u128;
        let r2 = r_mod_q.wrapping_mul(r_mod_q) % KYBER_Q as u128;
        let x_norm = x as u128 % KYBER_Q as u128;
        montgomery_reduce(x_norm.wrapping_mul(r2))
    }

    #[test]
    fn ntt_inv_roundtrip() {
        let mut rng = StdRng::seed_from_u64(123);
        for _ in 0..2 {
            let mut a = [0u64; KYBER_N];
            for v in a.iter_mut() {
                *v = rng.gen_range(0..KYBER_Q as u64);
            }
            let mut mont = [0u64; KYBER_N];
            for i in 0..KYBER_N {
                mont[i] = to_mont(a[i]);
            }
            ntt(&mut mont);
            invntt(&mut mont);
            for v in mont.iter_mut() {
                *v = montgomery_reduce(*v as u128);
            }
            for i in 0..KYBER_N {
                assert_eq!(a[i], mont[i], "idx {}", i);
            }
        }
    }

    #[test]
    fn ntt_scale_probe() {
        // Verify that NTT + invntt roundtrip works correctly with the scaling factor
        assert_eq!(
            INV_SCALE,
            144115188075855872u64,
            "inv_scale mismatch in test"
        );
        let mut a = [0u64; KYBER_N];
        a[0] = 1;
        let mut mont = [0u64; KYBER_N];
        for i in 0..KYBER_N {
            mont[i] = to_mont(a[i]);
        }
        ntt(&mut mont);
        invntt(&mut mont);
        for v in mont.iter_mut() {
            *v = montgomery_reduce(*v as u128);
        }
        // Impulse should roundtrip to impulse in normal domain.
        for (i, v) in mont.iter().enumerate() {
            let expected = if i == 0 { 1 } else { 0 };
            assert_eq!(*v, expected, "idx {} val {}", i, v);
        }
    }
}
