//
// Created by hcy_ray on 10/11/19.
//




#include <cassert>
#include <memory>

#include <libsnark/gadgetlib1/gadget.hpp>

using namespace libsnark;

template<typename FieldT>
class mul_cmp : public gadget<FieldT> {
private:
    /* no internal variables */
public:

    pb_variable<FieldT> x;
    pb_variable<FieldT> less_1;
    pb_variable_array<FieldT> less_or_equal;
    pb_variable_array<FieldT> less;

    pb_variable<FieldT> T1;
    pb_variable<FieldT> T2;
    int n_cmp;
    int n;
    std::shared_ptr<comparison_gadget<FieldT>> cmp_1;
    std::shared_ptr<comparison_gadget<FieldT>> cmp_2;
    std::vecotr<std::shared_ptr<disjunction_gadget<FieldT>>> disj_vec;
    mul_cmp(protoboard<FieldT> &pb,
            /*const pb_linear_combination_array<FieldT> &bits,*/
                  const pb_variable<FieldT> &x,
                  const std::string &annotation_prefix);

    void generate_r1cs_constraints();
    void generate_r1cs_witness();
};


#include "mul_cmp.cpp"
