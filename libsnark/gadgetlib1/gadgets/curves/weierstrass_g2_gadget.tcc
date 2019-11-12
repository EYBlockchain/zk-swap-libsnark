/** @file
 *****************************************************************************

 Implementation of interfaces for G2 gadgets.

 See weierstrass_g2_gadgets.hpp .

 *****************************************************************************
 * @author     This file is part of libsnark, developed by SCIPR Lab
 *             and contributors (see AUTHORS).
 * @copyright  MIT license (see LICENSE file)
 *****************************************************************************/

#ifndef WEIERSTRASS_G2_GADGET_TCC_
#define WEIERSTRASS_G2_GADGET_TCC_

#include <libff/algebra/scalar_multiplication/wnaf.hpp>

namespace libsnark {

template<typename ppT>
G2_variable<ppT>::G2_variable(protoboard<FieldT> &pb,
                              const std::string &annotation_prefix) :
    gadget<FieldT>(pb, annotation_prefix)
{
    X.reset(new Fqe_variable<ppT>(pb, FMT(annotation_prefix, " X")));
    Y.reset(new Fqe_variable<ppT>(pb, FMT(annotation_prefix, " Y")));

    all_vars.insert(all_vars.end(), X->all_vars.begin(), X->all_vars.end());
    all_vars.insert(all_vars.end(), Y->all_vars.begin(), Y->all_vars.end());
}

template<typename ppT>
G2_variable<ppT>::G2_variable(
    protoboard<FieldT> &pb,
    std::shared_ptr<Fqe_variable<ppT> > X,
    std::shared_ptr<Fqe_variable<ppT> > Y,
    const std::string &annotation_prefix
) : 
    gadget<FieldT>(pb, annotation_prefix),
    X(X),
    Y(Y)
{ }

template<typename ppT>
G2_variable<ppT>::G2_variable(protoboard<FieldT> &pb,
                              const libff::G2<other_curve<ppT> > &Q,
                              const std::string &annotation_prefix) :
    gadget<FieldT>(pb, annotation_prefix)
{
    libff::G2<other_curve<ppT> > Q_copy = Q;
    Q_copy.to_affine_coordinates();

    X.reset(new Fqe_variable<ppT>(pb, Q_copy.X(), FMT(annotation_prefix, " X")));
    Y.reset(new Fqe_variable<ppT>(pb, Q_copy.Y(), FMT(annotation_prefix, " Y")));

    all_vars.insert(all_vars.end(), X->all_vars.begin(), X->all_vars.end());
    all_vars.insert(all_vars.end(), Y->all_vars.begin(), Y->all_vars.end());
}

template<typename ppT>
void G2_variable<ppT>::generate_r1cs_witness(const libff::G2<other_curve<ppT> > &Q)
{
    libff::G2<other_curve<ppT> > Qcopy = Q;
    Qcopy.to_affine_coordinates();

    X->generate_r1cs_witness(Qcopy.X());
    Y->generate_r1cs_witness(Qcopy.Y());
}

template<typename ppT>
const libff::G2<other_curve<ppT>> G2_variable<ppT>::get_point()
{
    return libff::G2<other_curve<ppT>>(this->X->get_element(), this->Y->get_element(), libff::Fqe<other_curve<ppT>>::one());
}

template<typename ppT>
size_t G2_variable<ppT>::size_in_bits()
{
    return 2 * Fqe_variable<ppT>::size_in_bits();
}

template<typename ppT>
size_t G2_variable<ppT>::num_variables()
{
    return 2 * Fqe_variable<ppT>::num_variables();
}

template<typename ppT>
G2_checker_gadget<ppT>::G2_checker_gadget(protoboard<FieldT> &pb,
                                          const G2_variable<ppT> &Q,
                                          const std::string &annotation_prefix) :
    gadget<FieldT>(pb, annotation_prefix),
    Q(Q)
{
    Xsquared.reset(new Fqe_variable<ppT>(pb, FMT(annotation_prefix, " Xsquared")));
    Ysquared.reset(new Fqe_variable<ppT>(pb, FMT(annotation_prefix, " Ysquared")));

    compute_Xsquared.reset(new Fqe_sqr_gadget<ppT>(pb, *(Q.X), *Xsquared, FMT(annotation_prefix, " compute_Xsquared")));
    compute_Ysquared.reset(new Fqe_sqr_gadget<ppT>(pb, *(Q.Y), *Ysquared, FMT(annotation_prefix, " compute_Ysquared")));

    Xsquared_plus_a.reset(new Fqe_variable<ppT>((*Xsquared) + libff::G2<other_curve<ppT> >::coeff_a));
    Ysquared_minus_b.reset(new Fqe_variable<ppT>((*Ysquared) + (-libff::G2<other_curve<ppT> >::coeff_b)));

    curve_equation.reset(new Fqe_mul_gadget<ppT>(pb, *(Q.X), *Xsquared_plus_a, *Ysquared_minus_b, FMT(annotation_prefix, " curve_equation")));
}

template<typename ppT>
void G2_checker_gadget<ppT>::generate_r1cs_constraints()
{
    compute_Xsquared->generate_r1cs_constraints();
    compute_Ysquared->generate_r1cs_constraints();
    curve_equation->generate_r1cs_constraints();
}

template<typename ppT>
void G2_checker_gadget<ppT>::generate_r1cs_witness()
{
    compute_Xsquared->generate_r1cs_witness();
    compute_Ysquared->generate_r1cs_witness();
    Xsquared_plus_a->evaluate();
    curve_equation->generate_r1cs_witness();
}

template<typename ppT>
void test_G2_checker_gadget(const std::string &annotation)
{
    protoboard<libff::Fr<ppT> > pb;
    G2_variable<ppT> g(pb, "g");
    G2_checker_gadget<ppT> g_check(pb, g, "g_check");
    g_check.generate_r1cs_constraints();

    printf("positive test\n");
    g.generate_r1cs_witness(libff::G2<other_curve<ppT> >::one());
    g_check.generate_r1cs_witness();
    assert(pb.is_satisfied());

    printf("negative test\n");
    g.generate_r1cs_witness(libff::G2<other_curve<ppT> >::zero());
    g_check.generate_r1cs_witness();
    assert(!pb.is_satisfied());

    printf("number of constraints for G2 checker (Fr is %s)  = %zu\n", annotation.c_str(), pb.num_constraints());
}


template<typename ppT>
G2_add_gadget<ppT>::G2_add_gadget(protoboard<FieldT> &pb,
                                  const G2_variable<ppT> &A,
                                  const G2_variable<ppT> &B,
                                  const std::string &annotation_prefix) :
    gadget<FieldT>(pb, annotation_prefix),
    minus_one(FieldT::zero() - FieldT::one()),
    A(A),
    B(B),
    lambda(pb, FMT(annotation_prefix, ".lambda")),
    inv(pb, FMT(annotation_prefix, ".inv")),
    m_D(pb, FMT(annotation_prefix, ".D")),
    m_E(pb, FMT(annotation_prefix, ".E")),
    m_F(pb, FMT(annotation_prefix, ".F")),
    m_G(pb, FMT(annotation_prefix, ".G")),
    result(pb,
        std::make_shared<Fqe_variable<ppT>>(m_E + ((*(A.X) + *(B.X)) * minus_one)),
        std::make_shared<Fqe_variable<ppT>>(m_F + (*(A.Y) * minus_one)),
        FMT(annotation_prefix, ".result")),
    bxax_mul_inv_gadget(pb, *(B.X) + (*(A.X) * minus_one), inv, m_D, FMT(annotation_prefix, ".(B.X - A.X) * inv")),
    sqr_lambda_gadget(pb, lambda, m_E, FMT(annotation_prefix, ".lambda^2")),
    lambda_mul_axcx_gadget(pb, lambda, *(A.X) + (*(result.X) * minus_one), m_F, FMT(annotation_prefix, ".lambda * (A.X - C.X)")),
    lambda_mul_bxax_gadget(pb, lambda, *(B.X) + (*(A.X) * minus_one), m_G, FMT(annotation_prefix, ".lambda * (B.X - A.X)"))
{
    /*
      lambda = (B.y - A.y)/(B.x - A.x)
      C.x = lambda^2 - A.x - B.x
      C.y = lambda(A.x - C.x) - A.y

      Special cases:

      doubling: if B.y = A.y and B.x = A.x then lambda is unbound and
      C = (lambda^2, lambda^3)

      addition of negative point: if B.y = -A.y and B.x = A.x then no
      lambda can satisfy the first equation unless B.y - A.y = 0. But
      then this reduces to doubling.

      So we need to check that A.x - B.x != 0, which can be done by
      enforcing I * (B.x - A.x) = 1
    */
}

template<typename ppT>
void G2_add_gadget<ppT>::generate_r1cs_constraints()
{
    bxax_mul_inv_gadget.generate_r1cs_constraints();
    sqr_lambda_gadget.generate_r1cs_constraints();    
    lambda_mul_axcx_gadget.generate_r1cs_constraints();
    lambda_mul_bxax_gadget.generate_r1cs_constraints();

    // Multiply lambda by (B.X - A.X), result should be (B.Y - A.Y)
    const auto byay = *(B.Y) + (*(A.Y) * minus_one);
    int i = 0;
    for( const auto &x : m_G.all_vars ) {
        this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(
            { x },
            { ONE },
            { byay.all_vars[i] }),
            FMT(this->annotation_prefix, ".lambda * (B.X-A.X) == (B.Y-A.Y) [%d]", i));
        i += 1;
    }

    // Verify that B.X - A.X has a modulo inverse, enforcing it is not zero...
    i = 0;
    for( const auto &x : m_D.all_vars ) {
        const int expected = i == 0 ? 1 : 0;
        this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(
            { x },
            { ONE },
            expected),
            FMT(this->annotation_prefix, ".inv.c%d == %d", i, expected));
        i += 1;
    }
}

template<typename ppT>
void G2_add_gadget<ppT>::generate_r1cs_witness()
{
    const auto AX_val = A.X->get_element();
    const auto BX_val = B.X->get_element();
    const auto AY_val = A.Y->get_element();
    const auto BY_val = B.Y->get_element();

    assert( AX_val != BX_val || AY_val != BY_val ); // Points must be different

    const auto inv_val = (BX_val - AX_val).inverse();
    const auto lambda_val = (BY_val - AY_val) * inv_val;
    const auto CX_val = lambda_val.squared() - AX_val - BX_val;
    const auto CY_val = (lambda_val * (AX_val - CX_val)) - AY_val;

    result.X->generate_r1cs_witness(CX_val);
    result.Y->generate_r1cs_witness(CY_val);
    inv.generate_r1cs_witness(inv_val);
    lambda.generate_r1cs_witness(lambda_val);

    bxax_mul_inv_gadget.A.evaluate();
    bxax_mul_inv_gadget.generate_r1cs_witness();

    sqr_lambda_gadget.generate_r1cs_witness();

    lambda_mul_axcx_gadget.B.evaluate();
    lambda_mul_axcx_gadget.generate_r1cs_witness();

    lambda_mul_bxax_gadget.B.evaluate();
    lambda_mul_bxax_gadget.generate_r1cs_witness();
}

/**
* G2 addition gadget, where both inputs are constant
*/
template<typename ppT>
void test_G2_add_gadget_const(const std::string &annotation)
{
    typedef libff::Fr<ppT> FieldT;
    typedef libff::G2<other_curve<ppT>> G2T;

    protoboard<FieldT> pb;

    G2_variable<ppT> a_const(pb, G2T::one() + G2T::one(), "A");
    G2_variable<ppT> b_const(pb, G2T::one(), "B");

    G2_add_gadget<ppT> gadget(pb, a_const, b_const, "gadget");
    gadget.generate_r1cs_constraints();
    gadget.generate_r1cs_witness();
    assert(pb.is_satisfied());

    const auto expected_result = G2T::one() + G2T::one() + G2T::one();
    assert( gadget.result.get_point() == expected_result );

    printf("number of constraints for G2 constant addition (Fr is %s)  = %zu\n", annotation.c_str(), pb.num_constraints());
}


/**
* G2 addition gadget, where both inputs are variable
*/
template<typename ppT>
void test_G2_add_gadget_var(const std::string &annotation)
{
    typedef libff::Fr<ppT> FieldT;
    typedef libff::G2<other_curve<ppT>> G2T;

    protoboard<FieldT> pb;

    G2_variable<ppT> a_var(pb, "A");
    G2_variable<ppT> b_var(pb, "B");
    a_var.generate_r1cs_witness(G2T::one() + G2T::one());
    b_var.generate_r1cs_witness(G2T::one());

    G2_add_gadget<ppT> gadget(pb, a_var, b_var, "gadget");
    gadget.generate_r1cs_constraints();
    gadget.generate_r1cs_witness();
    assert(pb.is_satisfied());

    const auto expected_result = G2T::one() + G2T::one() + G2T::one();
    assert( gadget.result.get_point() == expected_result );

    printf("number of constraints for G2 variable addition (Fr is %s)  = %zu\n", annotation.c_str(), pb.num_constraints());
}


} // libsnark

#endif // WEIERSTRASS_G2_GADGET_TCC_
