/** @file
 *****************************************************************************

 Implementation of interfaces for pairing-check gadgets.

 See pairing_checks.hpp .

 *****************************************************************************
 * @author     This file is part of libsnark, developed by SCIPR Lab
 *             and contributors (see AUTHORS).
 * @copyright  MIT license (see LICENSE file)
 *****************************************************************************/

#ifndef PAIRING_CHECKS_TCC_
#define PAIRING_CHECKS_TCC_


namespace libsnark {

template<typename ppT>
check_e_equals_e_gadget<ppT>::check_e_equals_e_gadget(protoboard<FieldT> &pb,
                                                      const G1_precomputation<ppT> &lhs_G1,
                                                      const G2_precomputation<ppT> &lhs_G2,
                                                      const G1_precomputation<ppT> &rhs_G1,
                                                      const G2_precomputation<ppT> &rhs_G2,
                                                      const pb_variable<FieldT> &result,
                                                      const std::string &annotation_prefix) :
    gadget<FieldT>(pb, annotation_prefix),
    lhs_G1(lhs_G1),
    lhs_G2(lhs_G2),
    rhs_G1(rhs_G1),
    rhs_G2(rhs_G2),
    result(result)
{
    ratio.reset(new Fqk_variable<ppT>(pb, FMT(annotation_prefix, " ratio")));
    compute_ratio.reset(new e_over_e_miller_loop_gadget<ppT>(pb, lhs_G1, lhs_G2, rhs_G1, rhs_G2, *ratio, FMT(annotation_prefix, " compute_ratio")));
    check_finexp.reset(new final_exp_gadget<ppT>(pb, *ratio, result, FMT(annotation_prefix, " check_finexp")));
}

template<typename ppT>
void check_e_equals_e_gadget<ppT>::generate_r1cs_constraints()
{
    compute_ratio->generate_r1cs_constraints();
    check_finexp->generate_r1cs_constraints();
}

template<typename ppT>
void check_e_equals_e_gadget<ppT>::generate_r1cs_witness()
{
    compute_ratio->generate_r1cs_witness();
    check_finexp->generate_r1cs_witness();
}

template<typename ppT>
check_e_equals_ee_gadget<ppT>::check_e_equals_ee_gadget(protoboard<FieldT> &pb,
                                                        const G1_precomputation<ppT> &lhs_G1,
                                                        const G2_precomputation<ppT> &lhs_G2,
                                                        const G1_precomputation<ppT> &rhs1_G1,
                                                        const G2_precomputation<ppT> &rhs1_G2,
                                                        const G1_precomputation<ppT> &rhs2_G1,
                                                        const G2_precomputation<ppT> &rhs2_G2,
                                                        const pb_variable<FieldT> &result,
                                                        const std::string &annotation_prefix) :
    gadget<FieldT>(pb, annotation_prefix),
    lhs_G1(lhs_G1),
    lhs_G2(lhs_G2),
    rhs1_G1(rhs1_G1),
    rhs1_G2(rhs1_G2),
    rhs2_G1(rhs2_G1),
    rhs2_G2(rhs2_G2),
    result(result)
{
    ratio.reset(new Fqk_variable<ppT>(pb, FMT(annotation_prefix, " ratio")));
    compute_ratio.reset(new e_times_e_over_e_miller_loop_gadget<ppT>(pb, rhs1_G1, rhs1_G2, rhs2_G1, rhs2_G2, lhs_G1, lhs_G2, *ratio, FMT(annotation_prefix, " compute_ratio")));
    check_finexp.reset(new final_exp_gadget<ppT>(pb, *ratio, result, FMT(annotation_prefix, " check_finexp")));
}

template<typename ppT>
void check_e_equals_ee_gadget<ppT>::generate_r1cs_constraints()
{
    compute_ratio->generate_r1cs_constraints();
    check_finexp->generate_r1cs_constraints();
}

template<typename ppT>
void check_e_equals_ee_gadget<ppT>::generate_r1cs_witness()
{
    compute_ratio->generate_r1cs_witness();
    check_finexp->generate_r1cs_witness();
}



template<typename ppT>
pairing_product_gadget<ppT>::pairing_product_gadget(
    protoboard<FieldT> &pb,
    const std::vector<pairing_input_pair<ppT>> &pairs,
    const std::string &annotation_prefix
) :
    gadget<FieldT>(pb, annotation_prefix)
{
    assert( pairs.size() > 0 );
    result_is_one.allocate(pb, FMT(annotation_prefix, ".result_is_one"));

    // XXX: must be reserved, otherwise emplace_back will call destructor on miller loop during move which invalidates shared_ptr
    m_miller_results.reserve(pairs.size());
    m_miller_loops.reserve(pairs.size());
    if( pairs.size() > 1 ) {
        m_product_results.reserve(pairs.size() - 1);
        m_product.reserve(pairs.size() - 1);
    }

    int i = 0;
    for( const auto &p_ref : pairs )
    {
        m_miller_results.emplace_back(pb, FMT(annotation_prefix, ".result_%d", i));
        m_miller_loops.emplace_back(
            pb,
            p_ref.g1,
            p_ref.g2,
            m_miller_results[i],
            FMT(annotation_prefix, ".miller_loop_%d", i));

        if( i > 0 )
        {
            m_product_results.emplace_back(pb, FMT(annotation_prefix, ".product_result_%d", i));

            if( m_product_results.size() == 1 )
            {
                assert( m_miller_results.size() == 2 );
                // pr[0] = result[0] * result[1]
                m_product.emplace_back(
                    pb,
                    m_miller_results[0],
                    m_miller_results.back(),
                    m_product_results.back(),
                    FMT(annotation_prefix, ".product_%d", i));
            }
            else {
                // pr[i] = pr[i-1] * result[i]
                m_product.emplace_back(
                    pb,
                    m_product_results[ m_product_results.size() - 2 ] ,  // Previous product
                    m_miller_results.back(),
                    m_product_results.back(),
                    FMT(annotation_prefix, ".product_%d", i));
            }
        }

        i += 1;
    }

    m_final_exp.reset(new final_exp_gadget<ppT>(pb, raw_result(), result_is_one, FMT(annotation_prefix, ".check_is_one")));
}


template<typename ppT>
void pairing_product_gadget<ppT>::generate_r1cs_constraints()
{
    for( auto &m : m_miller_loops )
        m.generate_r1cs_constraints();

    for( auto &p : m_product )
        p.generate_r1cs_constraints();

    m_final_exp->generate_r1cs_constraints();
}


template<typename ppT>
void pairing_product_gadget<ppT>::generate_r1cs_witness()
{
    for( auto &m : m_miller_loops )
        m.generate_r1cs_witness();

    for( auto &p : m_product )
        p.generate_r1cs_witness();

    m_final_exp->generate_r1cs_witness();
}


template<typename ppT>
Fqk_variable<ppT>& pairing_product_gadget<ppT>::result()
{
    return *m_final_exp->result;
}


template<typename ppT>
Fqk_variable<ppT>& pairing_product_gadget<ppT>::raw_result()
{
    if( m_product_results.size() > 0 ) {
        return m_product_results.back();
    }

    // When there is only one pairing, and no product...
    return m_miller_results.back();
}


} // libsnark

#endif // PAIRING_CHECKS_TCC_
