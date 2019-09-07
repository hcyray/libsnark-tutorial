#include <stdlib.h>
#include <iostream>

#include "libff/algebra/fields/field_utils.hpp"
#include "libsnark/zk_proof_systems/ppzksnark/r1cs_ppzksnark/r1cs_ppzksnark.hpp"
#include "libsnark/common/default_types/r1cs_ppzksnark_pp.hpp"
#include "libsnark/gadgetlib1/pb_variable.hpp"
#include "libsnark/gadgetlib1/gadgets/basic_gadgets.hpp"
#include "gadget.hpp"
#include "util.hpp"

using namespace libsnark;
using namespace std;
int main()
{
     typedef libff::Fr<default_r1cs_ppzksnark_pp> FieldT;

  // Initialize the curve parameters

    default_r1cs_ppzksnark_pp::init_public_params();
    protoboard<FieldT> pb;
     
    int n = 31;
    pb_variable<FieldT> A, B, less, less_or_eq;
    A.allocate(pb, "A");
    B.allocate(pb, "B");
    less.allocate(pb, "less");
    less_or_eq.allocate(pb, "less_or_eq");

    comparison_gadget<FieldT> cmp(pb, n, A, B, less, less_or_eq, "cmp");
    cmp.generate_r1cs_constraints();
    int a = 10485700;
    int b = 10485900;
    pb.val(A) = FieldT(a);
    pb.val(B) = FieldT(b);

    cmp.generate_r1cs_witness();
    const r1cs_constraint_system<FieldT> constraint_system = pb.get_constraint_system();

    const r1cs_ppzksnark_keypair<default_r1cs_ppzksnark_pp> keypair = r1cs_ppzksnark_generator<default_r1cs_ppzksnark_pp>(constraint_system);

    const r1cs_ppzksnark_proof<default_r1cs_ppzksnark_pp> proof = r1cs_ppzksnark_prover<default_r1cs_ppzksnark_pp>(keypair.pk, pb.primary_input(), pb.auxiliary_input());

    bool verified = r1cs_ppzksnark_verifier_strong_IC<default_r1cs_ppzksnark_pp>(keypair.vk, pb.primary_input(), proof);
    cout << "result:" << endl;
    bool c1 = pb.val(less) == (a < b ? FieldT::one() : FieldT::zero());
    cout << c1 << endl;
    bool c2 = pb.val(less_or_eq) == (a <= b ? FieldT::one() : FieldT::zero());
    cout << c2 << endl;
    cout << pb.is_satisfied() << endl;
    cout << "Number of R1CS constraints: " << constraint_system.num_constraints() << endl;
    cout << "Primary (public) input: " << pb.primary_input() << endl;
    cout << "Auxiliary (private) input: " << pb.auxiliary_input() << endl;
    cout << "Verification status: " << verified << endl;
    return 0;
    }
