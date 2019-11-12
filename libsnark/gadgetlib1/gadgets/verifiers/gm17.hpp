#pragma once

#include <libsnark/gadgetlib1/gadgets/basic_gadgets.hpp>
#include <libsnark/gadgetlib1/gadgets/curves/weierstrass_g1_gadget.hpp>
#include <libsnark/gadgetlib1/gadgets/curves/weierstrass_g2_gadget.hpp>
#include <libsnark/gadgetlib1/gadgets/pairing/pairing_checks.hpp>
#include <libsnark/gadgetlib1/gadgets/pairing/pairing_params.hpp>
#include <libsnark/zk_proof_systems/ppzksnark/r1cs_se_ppzksnark/r1cs_se_ppzksnark.hpp>


namespace libsnark {


/**
* Holds a GM17 proof (but not its inputs)
* The A, B and C points are validated
*/
template<typename ppT>
class gm17_proof_var : public gadget<libff::Fr<ppT> > {
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

    gm17_proof_var(
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

    gm17_proof_var(
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
        const r1cs_se_ppzksnark_proof<other_curve<ppT>> &proof
    ) {
        A.generate_r1cs_witness(proof.A);
        m_A_checker.generate_r1cs_witness();

        B.generate_r1cs_witness(proof.B);
        m_B_checker.generate_r1cs_witness();

        C.generate_r1cs_witness(proof.C);
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
class gm17_vk_var : public gadget<libff::Fr<ppT> > {
public:
    typedef libff::Fr<ppT> FieldT;
    typedef G1_variable<ppT> G1VarT;
    typedef G2_variable<ppT> G2VarT;

    G1VarT G_alpha;	// G^{\alpha}
    G1VarT G_gamma;	// G^{\gamma}
    G2VarT H;			// H
    G2VarT H_beta;	// H^{\beta}
    G2VarT H_gamma;	// H^{\gamma}

    const size_t n_inputs;
    std::vector<G1VarT> query;

    std::vector<G1_checker_gadget<ppT>> m_g1_checkers;
    std::vector<G2_checker_gadget<ppT>> m_g2_checkers;

    void _init_checkers()
    {
        const auto annotation_prefix = this->annotation_prefix;

        m_g1_checkers.reserve(n_inputs + 3);
        m_g1_checkers.emplace_back(this->pb, G_alpha, FMT(annotation_prefix, ".G_alpha_checker"));
        m_g1_checkers.emplace_back(this->pb, G_gamma, FMT(annotation_prefix, ".G_gamma_checker"));

        assert( n_inputs > 0 );
        for( size_t i = 0; i < (n_inputs+1); i++ )
        {
            query.emplace_back(this->pb, FMT(annotation_prefix, ".input_%d", i));
            m_g1_checkers.emplace_back(this->pb, query.back(), FMT(annotation_prefix, ".query_checker_%d", i));
        }

        m_g2_checkers.reserve(3);
        m_g2_checkers.emplace_back(this->pb, H, FMT(annotation_prefix, ".H_checker"));
        m_g2_checkers.emplace_back(this->pb, H_beta, FMT(annotation_prefix, ".H_beta_checker"));
        m_g2_checkers.emplace_back(this->pb, H_gamma, FMT(annotation_prefix, ".H_gamma_checker"));
    }

    /**
    * Construct new variables to hold the verification key
    * For when the verification key is a secret input
    */
    gm17_vk_var(
        protoboard<FieldT> &pb,
        size_t _n_inputs,
        const std::string &annotation_prefix
    ) :
        gadget<FieldT>(pb, annotation_prefix),
        G_alpha(pb, FMT(annotation_prefix, ".G_alpha")),
        G_gamma(pb, FMT(annotation_prefix, ".G_gamma")),
        H(pb, FMT(annotation_prefix, ".H")),
        H_beta(pb, FMT(annotation_prefix, ".H_beta")),
        H_gamma(pb, FMT(annotation_prefix, ".H_gamma")),
        n_inputs(_n_inputs)
    {
        _init_checkers();
    }

    /**
    * Fill verification key from already existing variables
    * When the verification key comes from somewhere else within the circuit
    */
    gm17_vk_var(
        protoboard<FieldT> &pb,
        const G1VarT &G_alpha,
        const G1VarT &G_gamma,
        const G2VarT &H,
        const G2VarT &H_beta,
        const G2VarT &H_gamma,
        const std::vector<G1VarT> &IC,
        const std::string &annotation_prefix
    ) :
        gadget<FieldT>(pb, annotation_prefix),
        G_alpha(G_alpha),
        G_gamma(G_gamma),
        H(H),
        H_beta(H_beta),
        H_gamma(H_gamma),
        n_inputs(IC.size()-1),  // IC always includes the implicit 'ONE' constant as the first element
        query(IC)
    {
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
        const r1cs_se_ppzksnark_verification_key<T> &vk
    ) {
        G_alpha.generate_r1cs_witness(vk.G_alpha);
        G_gamma.generate_r1cs_witness(vk.G_gamma);
        H.generate_r1cs_witness(vk.H);
        H_beta.generate_r1cs_witness(vk.H_beta);
        H_gamma.generate_r1cs_witness(vk.H_gamma);

        assert( vk.query.size() == n_inputs + 1 );
        int i = 0;
        for( const auto& x: vk.query ) {
            query[i++].generate_r1cs_witness(x);
        }

        generate_r1cs_witness();
    }

    void print(const char *prefix="")
    {
        std::cout << prefix << ".G_alpha.X = "; this->pb.lc_val(G_alpha.X).print();
        std::cout << prefix << ".G_alpha.Y = "; this->pb.lc_val(G_alpha.Y).print();

        std::cout << prefix << ".G_gamma.X = "; this->pb.lc_val(G_gamma.X).print();
        std::cout << prefix << ".G_gamma.Y = "; this->pb.lc_val(G_gamma.Y).print();

		std::cout << prefix << ".H.X = "; H.X.get_element().print();
        std::cout << prefix << ".H.Y = "; H.Y.get_element().print();

        std::cout << prefix << ".H_beta.X = "; H_beta.X.get_element().print();
        std::cout << prefix << ".H_beta.Y = "; H_beta.Y.get_element().print();

        std::cout << prefix << ".H_gamma.X = "; H_gamma.X.get_element().print();
        std::cout << prefix << ".H_gamma.Y = "; H_gamma.Y.get_element().print();

        int i = 0;
        for( const auto &el : query )
        {
        	std::cout << prefix << ".query["<<i<<".X = "; this->pb.lc_val(el.X).print();
        	std::cout << prefix << ".query["<<i<<".Y = "; this->pb.lc_val(el.Y).print();
        	i += 1;
        }
    }
};


template<typename ppT>
class gm17_vk_preprocessor {
public:
    typedef libff::Fr<ppT> FieldT;
    typedef pb_variable<FieldT> FieldVarT;
    typedef G1_precomputation<ppT> G1precompT;
    typedef G2_precomputation<ppT> G2precompT;
    typedef G1_variable<ppT> G1VarT;
    typedef G2_variable<ppT> G2VarT;

    G1precompT G_alpha;
    precompute_G1_gadget<ppT> m_G_alpha_precomp;

    G1VarT neg_G_gamma;
    G1precompT G_gamma;
    precompute_G1_gadget<ppT> m_G_gamma_precomp;

    G2precompT H;
    precompute_G2_gadget<ppT> m_H_precomp;

    G2precompT H_beta;
    precompute_G2_gadget<ppT> m_H_beta_precomp;

    G2precompT H_gamma;
    precompute_G2_gadget<ppT> m_H_gamma_precomp;

    Fqk_variable<ppT> G_alpha_H_beta;
    miller_loop_gadget<ppT> m_G_alpha_H_beta_loop;

    gm17_vk_preprocessor(
        protoboard<FieldT> &pb,
        const gm17_vk_var<ppT> &vk,
        const std::string &annotation_prefix
    ) :
        // Precomputation gadget allocates the result variables
        m_G_alpha_precomp(pb, vk.G_alpha, G_alpha, FMT(annotation_prefix, ".G_alpha_precomp")),
        neg_G_gamma(vk.G_gamma.negate()),
        m_G_gamma_precomp(pb, neg_G_gamma, G_gamma, FMT(annotation_prefix, ".G_gamma_precomp")),
        m_H_precomp(pb, vk.H, H, FMT(annotation_prefix, ".H_precomp")),
        m_H_beta_precomp(pb, vk.H_beta, H_beta, FMT(annotation_prefix, ".H_beta_precomp")),
        m_H_gamma_precomp(pb, vk.H_gamma, H_gamma, FMT(annotation_prefix, ".H_gamma_precomp")),
        // Miller loop to precompute e(alpha,beta)
        G_alpha_H_beta(pb, FMT(annotation_prefix, ".G_alpha_H_beta")),
        m_G_alpha_H_beta_loop(pb, G_alpha, H_beta, G_alpha_H_beta, FMT(annotation_prefix, ".e(G_alpha,H_beta_loop)"))
    {
    }

    /* Verification key will be constant, no checker gadgets are necessary, only precomputation */
    gm17_vk_preprocessor(
        protoboard<FieldT> &pb,
        const r1cs_se_ppzksnark_verification_key<ppT> &vk,
        const std::string &annotation_prefix
    ) :
        // Precomputation gadget allocates the result variables
        m_G_alpha_precomp(pb, vk.G_alpha, G_alpha, FMT(annotation_prefix, ".G_alpha_precomp")),
        neg_G_gamma(vk.G_gamma.X, -vk.G_gamma.Y),
        m_G_gamma_precomp(pb, neg_G_gamma, G_gamma, FMT(annotation_prefix, ".G_gamma_precomp")),
        m_H_precomp(pb, vk.H, H, FMT(annotation_prefix, ".H_precomp")),
        m_H_beta_precomp(pb, vk.H_beta, H_beta, FMT(annotation_prefix, ".H_beta_precomp")),
        m_H_gamma_precomp(pb, vk.H_gamma, H_gamma, FMT(annotation_prefix, ".H_gamma_precomp")),
        // Miller loop to precompute e(alpha,beta)
        G_alpha_H_beta(pb, FMT(annotation_prefix, ".G_alpha_H_beta")),
        m_G_alpha_H_beta_loop(pb, G_alpha, H_beta, G_alpha_H_beta, FMT(annotation_prefix, ".e(G_alpha,H_beta_loop)"))
    {
    }

    void generate_r1cs_constraints()
    {
        m_G_alpha_precomp.generate_r1cs_constraints();
        m_G_gamma_precomp.generate_r1cs_constraints();
        m_H_precomp.generate_r1cs_constraints();
        m_H_beta_precomp.generate_r1cs_constraints();
        m_H_gamma_precomp.generate_r1cs_constraints();

        m_G_alpha_H_beta_loop.generate_r1cs_constraints();
    }

    void generate_r1cs_witness() 
    {
    	m_G_alpha_precomp.generate_r1cs_witness();
        m_G_gamma_precomp.generate_r1cs_witness();
        m_H_precomp.generate_r1cs_witness();
        m_H_beta_precomp.generate_r1cs_witness();
        m_H_gamma_precomp.generate_r1cs_witness();

        m_G_alpha_H_beta_loop.generate_r1cs_witness();
    }

    void print(const char *prefix="") {

    }
};




/**
* Holds the input bits
* XXX: duplicates gro16_inputbits_gadget
*/
template<typename ppT>
class gm17_inputbits_gadget : public gadget<libff::Fr<ppT>>
{
public:
    typedef libff::Fr<ppT> FieldT;

    const size_t inputs_count;
    pb_variable_array<FieldT> bits; // Contiguous array of bits

    gm17_inputbits_gadget(
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

    gm17_inputbits_gadget(
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
class gm17_verifier_gadget : public gadget<libff::Fr<ppT>> {
public:
    typedef G1_precomputation<ppT> G1precompT;
    typedef G2_precomputation<ppT> G2precompT;
    typedef libff::Fr<ppT> FieldT;

    G1_variable<ppT> m_acc_result;
    G1precompT m_acc_result_precomp;
    precompute_G1_gadget<ppT> m_acc_result_precomp_gadget;
    G1_multiscalar_mul_gadget<ppT> m_acc;

    // d = g1_add(proof.A, vk.G_alpha)
    G1_variable<ppT> d;
    G1_add_gadget<ppT> d_gadget;

    // e = g2_add(proof.B, vk.H_beta)
    //G2_variable<ppT> e; // XXX: G2_addition gadget owns output
    G2_add_gadget<ppT> e_gadget;

    // f = g1_neg(d)
    G1_variable<ppT> f;

    G1_precomputation<ppT> proof_C_precomp;
    precompute_G1_gadget<ppT> proof_C_precomp_gadget;

    // g = miller_loop(f, e)
    G1_precomputation<ppT> g_1;
    precompute_G1_gadget<ppT> g_1_gadget;
    G2_precomputation<ppT> g_2;
    precompute_G2_gadget<ppT> g_2_gadget;

    // assert ppg([a, b, c, g])
    pairing_product_gadget<ppT> ppg_abcg;

    // h = miller_loop(proof.A, vk.H_gamma)
    G1_precomputation<ppT> proof_A_precomp;
    precompute_G1_gadget<ppT> proof_A_precomp_gadget;
    G2_precomputation<ppT> proof_B_precomp;
    precompute_G2_gadget<ppT> proof_B_precomp_gadget;

    // assert ppg([h, j])
    pairing_product_gadget<ppT> ppg_hj;

    std::vector<precompute_G1_gadget<ppT>*> g1_precomp_gadgets;
    std::vector<precompute_G2_gadget<ppT>*> g2_precomp_gadgets;

    gm17_verifier_gadget(
        protoboard<FieldT> &pb,
        const gm17_proof_var<ppT> &proof,
        const gm17_vk_var<ppT> &vk,
        const gm17_vk_preprocessor<ppT> &vkp,
        const gm17_inputbits_gadget<ppT> &bits,
        const std::string &annotation_prefix
    ) :
        gadget<FieldT>(pb, annotation_prefix),

        m_acc_result(pb, ".acc"),   // psi = \sum_{i=0}^l input_i pvk.query[i]
        m_acc_result_precomp_gadget(pb, m_acc_result, m_acc_result_precomp, FMT(annotation_prefix, ".acc_precompute")),
        m_acc(pb,
              vk.query[0],
              {bits.bits.begin(), bits.bits.end()},
              FieldT::size_in_bits(),
              {vk.query.begin() + 1, vk.query.end()},
              m_acc_result,
              FMT(annotation_prefix, ".acc_gadget")),


        d(pb, FMT(annotation_prefix, ".d")),
        d_gadget(pb, proof.A, vk.G_alpha, d, FMT(annotation_prefix, ".d_gadget")),  // A+G^{\alpha}
        e_gadget(pb, proof.B, vk.H_beta, FMT(annotation_prefix, ".e_gadget")),      // B+H^{\beta}

        f(d.negate()),  // negate lhs, will provide same result as test1_l.unitary_inverse()

        proof_C_precomp_gadget(pb, proof.C, proof_C_precomp, FMT(annotation_prefix, ".proof_C_precomp_gadget")),    // precompute_G1(proof.C)

        g_1_gadget(pb, f, g_1, FMT(annotation_prefix, ".g_1_gadget")),                  // precompute_G1(A+G^{\alpha})
        g_2_gadget(pb, e_gadget.result, g_2, FMT(annotation_prefix, ".g_2_gadget")),    // precompute_G2(B+H^{\beta})

        // test1... e(A*G^{alpha}, B*H^{beta}) = e(G^{alpha}, H^{beta}) * e(G^{psi}, H^{gamma})
        ppg_abcg(pb,
            {
                pairing_input_pair<ppT>(g_1, g_2),                              // test1_l
                pairing_input_pair<ppT>(m_acc_result_precomp, vkp.H_gamma),     // test1_r2
                pairing_input_pair<ppT>(proof_C_precomp, vkp.H)                 // test1_r3
            },
            {vkp.G_alpha_H_beta},                                               // test1_r1
            FMT(annotation_prefix, ".ppg_abcg")),

        proof_A_precomp_gadget(pb, proof.A, proof_A_precomp, FMT(annotation_prefix, ".proof_A_precomp_gadget")),
        proof_B_precomp_gadget(pb, proof.B, proof_B_precomp, FMT(annotation_prefix, ".proof_B_precomp_gadget")),

        // test2... e(A, H^{gamma}) = e(G^{gamma}, B)
        ppg_hj(pb,
            {
                pairing_input_pair<ppT>(proof_A_precomp, vkp.H_gamma),
                pairing_input_pair<ppT>(vkp.G_gamma, proof_B_precomp)
            }, FMT(annotation_prefix, ".ppg_hj"))
    {
        g1_precomp_gadgets.emplace_back(&g_1_gadget);
        g1_precomp_gadgets.emplace_back(&proof_A_precomp_gadget);
        g1_precomp_gadgets.emplace_back(&proof_C_precomp_gadget);

        g2_precomp_gadgets.emplace_back(&g_2_gadget);
        g2_precomp_gadgets.emplace_back(&proof_B_precomp_gadget);
    }

    void generate_r1cs_witness()
    {
        m_acc.generate_r1cs_witness();
        m_acc_result_precomp_gadget.generate_r1cs_witness();

        d_gadget.generate_r1cs_witness();
        e_gadget.generate_r1cs_witness();
        proof_C_precomp_gadget.generate_r1cs_witness();
        g_1_gadget.generate_r1cs_witness();
        g_2_gadget.generate_r1cs_witness();
        proof_A_precomp_gadget.generate_r1cs_witness();
        proof_B_precomp_gadget.generate_r1cs_witness();

        for( auto &x : g1_precomp_gadgets ) {
            x->generate_r1cs_witness();
        }

        for( auto &x : g2_precomp_gadgets ) {
            x->generate_r1cs_witness();
        }

        ppg_abcg.generate_r1cs_witness();
        ppg_hj.generate_r1cs_witness();
    }

    void generate_r1cs_constraints()
    {
        m_acc.generate_r1cs_constraints();
        m_acc_result_precomp_gadget.generate_r1cs_constraints();

        d_gadget.generate_r1cs_constraints();
        e_gadget.generate_r1cs_constraints();
        proof_C_precomp_gadget.generate_r1cs_constraints();
        g_1_gadget.generate_r1cs_constraints();
        g_2_gadget.generate_r1cs_constraints();
        proof_A_precomp_gadget.generate_r1cs_constraints();
        proof_B_precomp_gadget.generate_r1cs_constraints();

        for( auto &x : g1_precomp_gadgets ) {
            x->generate_r1cs_constraints();
        }

        for( auto &x : g2_precomp_gadgets ) {
            x->generate_r1cs_constraints();
        }

        ppg_abcg.generate_r1cs_constraints();
        this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(ppg_abcg.result_is_one, 1, 1), FMT(this->annotation_prefix, ".ppg_abcg.result must be 1"));

        ppg_hj.generate_r1cs_constraints();
        this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(ppg_hj.result_is_one, 1, 1), FMT(this->annotation_prefix, ".ppg_hj.result must be 1"));
    }

    void print(const char *prefix="") {
        std::cout << prefix << ".m_acc_result.X = "; this->pb.lc_val(m_acc_result.X).print();
        std::cout << prefix << ".m_acc_result.Y = "; this->pb.lc_val(m_acc_result.Y).print();        
    }
};


// libsnark
}