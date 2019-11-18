#pragma once

#include <libsnark/gadgetlib1/gadgets/basic_gadgets.hpp>
#include <libsnark/gadgetlib1/gadgets/curves/weierstrass_g1_gadget.hpp>
#include <libsnark/gadgetlib1/gadgets/curves/weierstrass_g2_gadget.hpp>
#include <libsnark/gadgetlib1/gadgets/pairing/pairing_checks.hpp>
#include <libsnark/gadgetlib1/gadgets/pairing/pairing_params.hpp>
#include <libsnark/zk_proof_systems/ppzksnark/r1cs_gg_ppzksnark/r1cs_gg_ppzksnark.hpp>

namespace libsnark {


/**
* Holds a Groth16 proof (but not its inputs)
* The A, B and C points are validated
*/
template<typename ppT>
class gro16_proof_var : public gadget<libff::Fr<ppT> > {
public:
    typedef libff::Fr<ppT> FieldT;
    typedef G1_variable<ppT> G1VarT;
    typedef G2_variable<ppT> G2VarT;
    typedef pb_variable<FieldT> FieldVarT;

    G1VarT A;
    G2VarT B;
    G1VarT C;

    // XXX: do we need a mode where we don't validate the proof points?
    G1_checker_gadget<ppT> m_A_checker;
    G2_checker_gadget<ppT> m_B_checker;
    G1_checker_gadget<ppT> m_C_checker;

    gro16_proof_var(
        protoboard<FieldT> &pb,
        const G1VarT &_A,
        const G2VarT &_B,
        const G1VarT &_C,
        const std::string &annotation_prefix
    ) :
        gadget<FieldT>(pb, annotation_prefix),
        A(_A),
        B(_B),
        C(_C),
        m_A_checker(pb, A, FMT(annotation_prefix, ".A_checker")),
        m_B_checker(pb, B, FMT(annotation_prefix, ".B_checker")),
        m_C_checker(pb, C, FMT(annotation_prefix, ".C_checker"))
    { }

    gro16_proof_var(
        protoboard<FieldT> &pb,
        const std::string &annotation_prefix
    ) :
        gadget<FieldT>(pb, annotation_prefix),
        A(pb, FMT(annotation_prefix, ".A")),
        B(pb, FMT(annotation_prefix, ".B")),
        C(pb, FMT(annotation_prefix, ".C")),
        m_A_checker(pb, A, FMT(annotation_prefix, ".A_checker")),
        m_B_checker(pb, B, FMT(annotation_prefix, ".B_checker")),
        m_C_checker(pb, C, FMT(annotation_prefix, ".C_checker"))
    {

    }

    void generate_r1cs_constraints()
    {
        m_A_checker.generate_r1cs_constraints();
        m_B_checker.generate_r1cs_constraints();
        m_C_checker.generate_r1cs_constraints();
    }

    /** Fill variables from proof with inputs */
    void generate_r1cs_witness(
        const r1cs_gg_ppzksnark_proof<other_curve<ppT>> &proof
    ) {
        // A and C need to be negated, so the first term in each pairing is negative
        // e(A*B) * e(-IC*gamma) * e(-C*delta) * (-alpha*gamma) == 1
        A.generate_r1cs_witness(proof.g_A);
        m_A_checker.generate_r1cs_witness();

        B.generate_r1cs_witness(proof.g_B);
        m_B_checker.generate_r1cs_witness();

        C.generate_r1cs_witness(-proof.g_C);
        m_C_checker.generate_r1cs_witness();
    }

    void print(const char *prefix="")
    {
        std::cout << prefix << ".A.X = "; this->pb.lc_val(A.X).print();
        std::cout << prefix << ".A.Y = "; this->pb.lc_val(A.Y).print();
        std::cout << prefix << ".B.X = "; this->B.X->get_element().print();
        std::cout << prefix << ".B.Y = "; this->B.Y->get_element().print();
        std::cout << prefix << ".C.X = "; this->pb.lc_val(C.X).print();
        std::cout << prefix << ".C.Y = "; this->pb.lc_val(C.Y).print();
    }
};


/**
* Holds a Groth16 verification key as variables
* The points of the verification key are validated
* This will be given to the preprocessor gadget
*/
template<typename ppT>
class gro16_vk_var : public gadget<libff::Fr<ppT> > {
public:
    typedef libff::Fr<ppT> FieldT;
    typedef G1_variable<ppT> G1VarT;
    typedef G2_variable<ppT> G2VarT;

    G1VarT m_alpha;
    G2VarT m_beta;
    G2VarT m_gamma;
    G2VarT m_delta;

    G1VarT m_IC_base;

    const size_t n_inputs;
    std::vector<G1VarT> m_IC;

    std::vector<G1_checker_gadget<ppT>> m_g1_checkers;
    std::vector<G2_checker_gadget<ppT>> m_g2_checkers;

    void _init_checkers()
    {
        const auto annotation_prefix = this->annotation_prefix;

        m_g1_checkers.reserve(n_inputs + 2);
        m_g1_checkers.emplace_back(this->pb, m_alpha, FMT(annotation_prefix, ".alpha_checker"));
        m_g1_checkers.emplace_back(this->pb, m_IC_base, FMT(annotation_prefix, ".IC_base"));

        assert( n_inputs > 0 );
        for( size_t i = 0; i < n_inputs; i++ )
        {
            m_g1_checkers.emplace_back(this->pb, m_IC[i], FMT(annotation_prefix, ".IC_checker_%d", i));
        }

        m_g2_checkers.reserve(3);
        m_g2_checkers.emplace_back(this->pb, m_beta, FMT(annotation_prefix, ".beta_checker"));
        m_g2_checkers.emplace_back(this->pb, m_gamma, FMT(annotation_prefix, ".gamma_checker"));
        m_g2_checkers.emplace_back(this->pb, m_delta, FMT(annotation_prefix, ".delta_checker"));
    }

    /**
    * Construct new variables to hold the verification key
    * For when the verification key is a secret input
    */
    gro16_vk_var(
        protoboard<FieldT> &pb,
        size_t _n_inputs,
        const std::string &annotation_prefix
    ) :
        gadget<FieldT>(pb, annotation_prefix),
        m_alpha(pb, FMT(annotation_prefix, ".alpha")),
        m_beta(pb, FMT(annotation_prefix, ".beta")),
        m_gamma(pb, FMT(annotation_prefix, ".gamma")),
        m_delta(pb, FMT(annotation_prefix, ".delta")),
        m_IC_base(pb, FMT(annotation_prefix, ".IC_base")),
        n_inputs(_n_inputs)
    {
        assert( n_inputs > 0 );
        for( size_t i = 0; i < n_inputs; i++ )
        {
            m_IC.emplace_back(this->pb, FMT(annotation_prefix, ".input_%d", i));
        }

        _init_checkers();
    }

    /**
    * Use a static verification key
    */
    gro16_vk_var(
        protoboard<FieldT> &pb,
        const r1cs_gg_ppzksnark_verification_key<other_curve<ppT>> &vk,
        const std::string &annotation_prefix
    ) :
        gadget<FieldT>(pb, annotation_prefix),
        m_alpha(pb, -vk.alpha_g1, FMT(annotation_prefix, ".alpha")),
        m_beta(pb, vk.beta_g2, FMT(annotation_prefix, ".beta")),
        m_gamma(pb, vk.gamma_g2, FMT(annotation_prefix, ".gamma")),
        m_delta(pb, vk.delta_g2, FMT(annotation_prefix, ".delta")),
        m_IC_base(pb, -vk.gamma_ABC_g1.first, FMT(annotation_prefix, ".IC_base")),
        n_inputs(vk.gamma_ABC_g1.rest.size())
    {
        m_IC.reserve(n_inputs);
        for( unsigned i = 0; i < n_inputs; i++ )
        {
            m_IC.emplace_back(pb, -vk.gamma_ABC_g1.rest.values[i], FMT(annotation_prefix, ".IC[%u]", i));
        }

        _init_checkers();
    }

    void generate_r1cs_constraints()
    {
        for( auto &gadget : m_g1_checkers )
            gadget.generate_r1cs_constraints();

        for( auto &gadget : m_g2_checkers )
            gadget.generate_r1cs_constraints();
    }

    void generate_r1cs_witness()
    {
        for( auto &gadget : m_g1_checkers )
            gadget.generate_r1cs_witness();

        for( auto &gadget : m_g2_checkers )
            gadget.generate_r1cs_witness();
    }

    template<typename T>
    void generate_r1cs_witness(
        const r1cs_gg_ppzksnark_verification_key<T> &vk
    ) {
        m_alpha.generate_r1cs_witness(-vk.alpha_g1);
        m_beta.generate_r1cs_witness(vk.beta_g2);
        m_gamma.generate_r1cs_witness(vk.gamma_g2);
        m_delta.generate_r1cs_witness(vk.delta_g2);

        // IC needs to be negated for the sum
        m_IC_base.generate_r1cs_witness(-(vk.gamma_ABC_g1.first));
        assert( vk.gamma_ABC_g1.rest.size() == n_inputs );
        int i = 0;
        for( const auto& x: vk.gamma_ABC_g1.rest.values ) {
            m_IC[i++].generate_r1cs_witness(-x);
        }

        generate_r1cs_witness();
    }

    void print(const char *prefix="")
    {
        std::cout << prefix << ".alpha = "; this->pb.lc_val(m_alpha.X).print();
    }
};


/**
* Given the verification key variables
* Pre-compute the miller loop coefficients
* And the product of e(alpha,beta)
* This becomes cheaper when used multiple times, to avoid computing coefficients again
*/
template<typename ppT>
class gro16_vk_preprocessor {
public:
    typedef libff::Fr<ppT> FieldT;
    typedef pb_variable<FieldT> FieldVarT;
    typedef G1_precomputation<ppT> G1precompT;
    typedef G2_precomputation<ppT> G2precompT;
    typedef G1_variable<ppT> G1VarT;
    typedef G2_variable<ppT> G2VarT;

    G1precompT m_alpha;
    precompute_G1_gadget<ppT> m_alpha_precomp;

    G2precompT m_beta;
    precompute_G2_gadget<ppT> m_beta_precomp;

    G2precompT m_gamma;
    precompute_G2_gadget<ppT> m_gamma_precomp;

    G2precompT m_delta;
    precompute_G2_gadget<ppT> m_delta_precomp;

    Fqk_variable<ppT> m_alphabeta;
    miller_loop_gadget<ppT> m_alphabeta_loop;

    G1VarT m_IC_base;
    std::vector<G1VarT> m_IC;

    gro16_vk_preprocessor(
        protoboard<FieldT> &pb,
        const gro16_vk_var<ppT> &vk,
        const std::string &annotation_prefix
    ) :
        // Precomputation gadget allocates the result variables
        m_alpha_precomp(pb, vk.m_alpha, m_alpha, FMT(annotation_prefix, ".alpha_precomp")),
        m_beta_precomp(pb, vk.m_beta, m_beta, FMT(annotation_prefix, ".beta_precomp")),
        m_gamma_precomp(pb, vk.m_gamma, m_gamma, FMT(annotation_prefix, ".gamma_precomp")),
        m_delta_precomp(pb, vk.m_delta, m_delta, FMT(annotation_prefix, ".delta_precomp")),
        // Miller loop to precompute e(alpha,beta)
        m_alphabeta(pb, FMT(annotation_prefix, ".alphabeta")),
        m_alphabeta_loop(pb, m_alpha, m_beta, m_alphabeta, FMT(annotation_prefix, ".alphabeta_miller_loop")),
        // Input commitment
        m_IC_base(vk.m_IC_base),
        m_IC(vk.m_IC)
    {
    }

    /* Verification key will be constant, no checker gadgets are necessary, only precomputation */
    /*
    gro16_vk_preprocessor(
        protoboard<FieldT> &pb,
        const r1cs_gg_ppzksnark_verification_key<ppT> &vk,
        const std::string &annotation_prefix
    ) :
        // Precomputation gadget allocates the result variables
        m_alpha_precomp(pb, vk.alpha_g1, m_alpha, FMT(annotation_prefix, ".alpha_precomp")),
        m_beta_precomp(pb, vk.beta_g2, m_beta, FMT(annotation_prefix, ".beta_precomp")),
        m_gamma_precomp(pb, vk.gamma_g2, m_gamma, FMT(annotation_prefix, ".gamma_precomp")),
        m_delta_precomp(pb, vk.delta_g2, m_delta, FMT(annotation_prefix, ".delta_precomp")),
        // Miller loop to precompute e(alpha,beta)
        m_alphabeta(pb, FMT(annotation_prefix, ".alphabeta")),
        m_alphabeta_loop(pb, m_alpha, m_beta, m_alphabeta, FMT(annotation_prefix, ".alphabeta_miller_loop")),
        // Input commitment
        m_IC_base(vk.gamma_ABC_g1.first),
        m_IC(vk.gamma_ABC_g1.rest)
    {
    }
    */

    void generate_r1cs_constraints()
    {
        m_alpha_precomp.generate_r1cs_constraints();
        m_beta_precomp.generate_r1cs_constraints();
        m_gamma_precomp.generate_r1cs_constraints();
        m_delta_precomp.generate_r1cs_constraints();

        m_alphabeta_loop.generate_r1cs_constraints();
    }

    void generate_r1cs_witness() 
    {
        m_alpha_precomp.generate_r1cs_witness();
        m_beta_precomp.generate_r1cs_witness();
        m_gamma_precomp.generate_r1cs_witness();
        m_delta_precomp.generate_r1cs_witness();

        m_alphabeta_loop.generate_r1cs_witness();
    }

    void print(const char *prefix="") {

    }
};


/**
* Holds the input bits
*/
template<typename ppT>
class gro16_inputbits_gadget : public gadget<libff::Fr<ppT>>
{
public:
    typedef libff::Fr<ppT> FieldT;

    const size_t inputs_count;
    pb_variable_array<FieldT> bits; // Contiguous array of bits

    gro16_inputbits_gadget(
        protoboard<FieldT> &pb,
        const size_t n_inputs,
        const std::string &annotation_prefix
    ) :
        gadget<FieldT>(pb, annotation_prefix),
        inputs_count(n_inputs)
    {
        assert( inputs_count > 0 );
        const size_t n_input_bits = FieldT::size_in_bits() * inputs_count;
        bits.allocate(pb, n_input_bits, FMT(annotation_prefix, ".bits"));
    }

    gro16_inputbits_gadget(
        protoboard<FieldT> &pb,
        const pb_variable_array<FieldT> bits,
        const std::string &annotation_prefix
    ) :
        gadget<FieldT>(pb, annotation_prefix),
        inputs_count(bits.size() / FieldT::size_in_bits()),
        bits(bits)
    {
        assert( inputs_count > 0 );
        assert( (bits.size() % FieldT::size_in_bits()) == 0 );
    }

    void generate_r1cs_witness()
    {
        // ... nothing to do
        // ... variables have been passed in via constructor
        // ... values are assumed to have been populated elsewhere
    }

    /** Fill input bits from field elements */
    template<typename T>
    void generate_r1cs_witness(const std::vector<T> inputs)
    {
        assert( inputs_count == inputs.size() );

        int i = 0;

        for (const auto &el : inputs)
        {
            const auto el_bits = libff::convert_field_element_to_bit_vector(el, T::size_in_bits());
            for( const auto b : el_bits ) {
                this->pb.val(bits[i++]) = (b ? 1 : 0);
            }
        }
    }

    void generate_r1cs_constraints(bool enforce_bitness = true)
    {
        if( enforce_bitness )
        {
            int i = 0;
            for( auto &bit_var : bits )
            {
                generate_boolean_r1cs_constraint<FieldT>(this->pb, bit_var, FMT(this->annotation_prefix, ".bitness[%d]", i));
                i += 1;
            }
        }
    }

    void print(const char *prefix="") {
    }
};



template<typename ppT>
class gro16_verifier_gadget : public gadget<libff::Fr<ppT>> {
public:
    typedef G1_precomputation<ppT> G1precompT;
    typedef G2_precomputation<ppT> G2precompT;
    typedef libff::Fr<ppT> FieldT;

    G1precompT m_A;
    precompute_G1_gadget<ppT> m_A_precomp;

    G2precompT m_B;
    precompute_G2_gadget<ppT> m_B_precomp;

    G1precompT m_C;
    precompute_G1_gadget<ppT> m_C_precomp;

    const G1_variable<ppT> m_acc_result;
    G1precompT m_acc_result_precomp;
    precompute_G1_gadget<ppT> m_acc_result_precomp_gadget;

    G1_multiscalar_mul_gadget<ppT> m_acc;

    pairing_product_gadget<ppT> m_ppg;
    // TODO: calculate input commitment...

    gro16_verifier_gadget(
        protoboard<FieldT> &pb,
        const gro16_proof_var<ppT> &proof,
        const gro16_vk_preprocessor<ppT> &vkp,
        const gro16_inputbits_gadget<ppT> &bits,
        const std::string &annotation_prefix
    ) :
        gadget<FieldT>(pb, annotation_prefix),
        m_A_precomp(pb, proof.A, m_A, FMT(annotation_prefix, ".A_precompute")),
        m_B_precomp(pb, proof.B, m_B, FMT(annotation_prefix, ".B_precompute")),
        m_C_precomp(pb, proof.C, m_C, FMT(annotation_prefix, ".C_precompute")),
        m_acc_result(pb, ".acc"),
        m_acc_result_precomp_gadget(pb, m_acc_result, m_acc_result_precomp, FMT(annotation_prefix, ".C_precompute")),
        m_acc(pb,
              vkp.m_IC_base,
              {bits.bits.begin(), bits.bits.end()},
              FieldT::size_in_bits(),
              vkp.m_IC,
              m_acc_result,
              FMT(annotation_prefix, ".acc_gadget")),
        m_ppg(pb,
              {
                pairing_input_pair<ppT>(m_acc_result_precomp, vkp.m_gamma),
                pairing_input_pair<ppT>(m_C, vkp.m_delta),
                pairing_input_pair<ppT>(m_A, m_B)
              },
              {vkp.m_alphabeta},
              FMT(annotation_prefix, ".pairing_product"))
    {
        // ... nothing more to do here
    }

    void generate_r1cs_witness()
    {
        m_A_precomp.generate_r1cs_witness();
        m_B_precomp.generate_r1cs_witness();
        m_C_precomp.generate_r1cs_witness();
        m_acc.generate_r1cs_witness();
        m_acc_result_precomp_gadget.generate_r1cs_witness();
        m_ppg.generate_r1cs_witness();
    }

    void generate_r1cs_constraints()
    {
        m_A_precomp.generate_r1cs_constraints();
        m_B_precomp.generate_r1cs_constraints();
        m_C_precomp.generate_r1cs_constraints();
        m_acc.generate_r1cs_constraints();
        m_acc_result_precomp_gadget.generate_r1cs_constraints();
        m_ppg.generate_r1cs_constraints();

        this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(m_ppg.result_is_one, 1, 1), FMT(this->annotation_prefix, ".result must be 1"));
    }

    void print(const char *prefix="") {
        std::cout << prefix << ".m_acc_result.X = "; this->pb.lc_val(m_acc_result.X).print();
        std::cout << prefix << ".m_acc_result.Y = "; this->pb.lc_val(m_acc_result.Y).print();        
    }
};


} // libsnark

