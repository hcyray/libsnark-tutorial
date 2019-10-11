//
// Created by hcy_ray on 10/11/19.
//




using namespace libsnark;


template<typename FieldT>
mul_cmp<FieldT>::mul_cmp(protoboard<FieldT> &pb, const pb_variable<FieldT> &x,
        const std::string &annotation_prefix):
        gadget<FieldT>(pb, " multiple comparison") , x(x) {
    n = 63;
    n_cmp = 1; // number of comparision
    T1.allocate(pb, "smaller threshold 1");
    T2.allocate(pb, "larger threshold 1");
    relation.allocate(pb, n_cmp * 2, "less and less_or_eq");
   //less_or_eq_1.allocate(pb, n_cmp * 2, "less_or_eq 1");
    conj.allocate(pb, n_cmp, "not false")
    cmp1.reset(new comparison_gadget<FieldT>(pb, n, T1, x, relation[0], relation[1], "cmp_1"))
    cmp2.reset(new comparison_gadget<FieldT>(pb, n, x, T2, relation[2], relation[3], "cmp_2"))
    for (int i = 0; i < n_cmp; i++) {
        disj_vec.emplace_back(new disjunction_gadget<FieldT>(pb,
                                                             pb_variable_array<FieldT>(relation.at(i*2),relation.at(i*2)+1),
                                                             not_all_zeros,
                                                             FMT(this->annotation_prefix, " all_zeros_test")))
    }
}



template<typename FieldT>
void  mul_cmp<FieldT>::generate_r1cs_constraints()
{
    cmp1->generate_r1cs_constraints();
    cmp2->generate_r1cs_constraints();
    for (int i = 0; i < n_cmp; i++) {
        disj_vec[i] -> generate_r1cs_constraints();
    }


}


template<typename FieldT>
void  mul_cmp<FieldT>::generate_r1cs_witness()
{

}