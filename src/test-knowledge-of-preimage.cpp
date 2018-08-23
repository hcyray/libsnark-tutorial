// Adapted from an example by Christian Lundkvist and the test for the sha256 gadget in libsnark
// MIT License

#include <libff/algebra/fields/field_utils.hpp>
#include <libff/common/default_types/ec_pp.hpp>
#include <libff/common/profiling.hpp>
#include <libff/common/utils.hpp>
#include <libsnark/common/default_types/r1cs_ppzksnark_pp.hpp>
#include <libsnark/gadgetlib1/gadgets/hashes/sha256/sha256_gadget.hpp>
#include <libsnark/gadgetlib1/pb_variable.hpp>
#include <libsnark/zk_proof_systems/ppzksnark/r1cs_ppzksnark/r1cs_ppzksnark.hpp>
#include <util.hpp>

using namespace libsnark;
using namespace std;

int main()
{
  default_r1cs_ppzksnark_pp::init_public_params();
  typedef libff::Fr<default_r1cs_ppzksnark_pp> FieldT;

  protoboard<FieldT> pb;

  digest_variable<FieldT> output(pb, SHA256_digest_size, "output");
  digest_variable<FieldT> left(pb, SHA256_digest_size, "left");
  digest_variable<FieldT> right(pb, SHA256_digest_size, "right");

  pb.set_input_sizes(1);
  sha256_two_to_one_hash_gadget<FieldT> f(pb, left, right, output, "f");

  f.generate_r1cs_constraints();

  const libff::bit_vector left_bv  = libff::int_list_to_bits({0x426bc2d8, 0x4dc86782, 0x81e8957a, 0x409ec148, 0xe6cffbe8, 0xafe6ba4f, 0x9c6f1978, 0xdd7af7e9}, 32);
  const libff::bit_vector right_bv = libff::int_list_to_bits({0x038cce42, 0xabd366b8, 0x3ede7e00, 0x9130de53, 0x72cdf73d, 0xee825114, 0x8cb48d1b, 0x9af68ad0}, 32);
  const libff::bit_vector hash_bv  = libff::int_list_to_bits({0xeffd0b7f, 0x1ccba116, 0x2ee816f7, 0x31c62b48, 0x59305141, 0x990e5c0a, 0xce40d33d, 0x0b1167d1}, 32);

  left.generate_r1cs_witness(left_bv);
  right.generate_r1cs_witness(right_bv);
  f.generate_r1cs_witness();
  output.generate_r1cs_witness(hash_bv);

  const r1cs_constraint_system<FieldT> constraint_system = pb.get_constraint_system();
  const r1cs_ppzksnark_keypair<default_r1cs_ppzksnark_pp> keypair = r1cs_ppzksnark_generator<default_r1cs_ppzksnark_pp>(constraint_system);
  const r1cs_ppzksnark_proof<default_r1cs_ppzksnark_pp> proof = r1cs_ppzksnark_prover<default_r1cs_ppzksnark_pp>(keypair.pk, pb.primary_input(), pb.auxiliary_input());
  bool verified = r1cs_ppzksnark_verifier_strong_IC<default_r1cs_ppzksnark_pp>(keypair.vk, pb.primary_input(), proof);

  ofstream cout("output.txt");
  cout << "Number of R1CS constraints: " << constraint_system.num_constraints() << endl;
  cout << "Primary (public) input: " << pb.primary_input() << endl;
  cout << "Auxiliary (private) input: " << pb.auxiliary_input() << endl;
  cout << "Verification status: " << verified << endl;

  const r1cs_ppzksnark_verification_key<default_r1cs_ppzksnark_pp> vk = keypair.vk;

  print_vk_to_file<default_r1cs_ppzksnark_pp>(vk, "../build/vk_data");
  print_proof_to_file<default_r1cs_ppzksnark_pp>(proof, "../build/proof_data");

  return 0;
}
