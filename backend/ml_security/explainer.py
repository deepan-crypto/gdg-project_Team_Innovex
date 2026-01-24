"""
Multi-level explanation generator for ML security issues
Beginner, Intermediate, Advanced explanations
"""

from typing import Dict

class SecurityExplainer:
    """Generate explanations at different technical levels"""
    
    EXPLANATIONS = {
        'backdoor': {
            'beginner': (
                "A backdoor is a hidden trigger in a model that makes it behave incorrectly. "
                "Imagine a stop sign that only fools a car from a specific angle - "
                "the model learned to recognize that exact angle and misclassify it. "
                "This is dangerous because the model works fine normally, but fails in specific cases."
            ),
            'intermediate': (
                "Backdoors are trojan attacks on ML models. A attacker poisons training data "
                "with trigger patterns (e.g., specific pixel patterns) coupled to wrong labels. "
                "The model learns this backdoor along with normal decision boundary. "
                "Detection is hard because models are black boxes - we can't easily inspect weights."
            ),
            'advanced': (
                "Backdoor triggers can be designed as semantic patterns, physical adversarial patches, "
                "or spectral artifacts. Detection uses activation clustering, pruning, "
                "or spectral analysis. Defenses include data sanitization, model distillation, "
                "and certified defenses. Neural cleanse and activation clustering are common methods."
            )
        },
        'extraction': {
            'beginner': (
                "Model extraction is when someone copies your AI model. "
                "If your model is available online and returns all prediction scores, "
                "an attacker can query it thousands of times to learn how it works, "
                "then build their own copy. This steals intellectual property."
            ),
            'intermediate': (
                "Model extraction via prediction APIs: attacker queries endpoint with varied inputs, "
                "collects predictions, trains substitute model via knowledge distillation. "
                "With full softmax outputs, extraction accuracy > 95%. Defenses: rate limiting, "
                "top-k output (not full distribution), output perturbation, monitoring."
            ),
            'advanced': (
                "Functional model extraction via membership inference queries. "
                "Attacker exploits gradient leakage or confidence scores to reverse-engineer model. "
                "Countermeasures: differential privacy, gradient clipping, secure aggregation, "
                "homomorphic encryption for inference. See Papernot et al. for PATE framework."
            )
        },
        'membership_inference': {
            'beginner': (
                "Membership inference checks if specific person's data was used to train the model. "
                "If the model is overtrained (memorizes), it gives high confidence on training data "
                "but low on new data. Attackers can exploit this to identify private records. "
                "This is a privacy violation."
            ),
            'intermediate': (
                "MIAs use confidence scores or loss values. Models that overfit have lower loss/higher "
                "confidence on member samples. Via multiple queries, attacker builds probability distribution "
                "and sets threshold. Modern attacks achieve ~90% accuracy at identifying members. "
                "Defenses: regularization, early stopping, differential privacy."
            ),
            'advanced': (
                "Modern MIAs use meta-classifiers trained on model confidence curves. "
                "Attacks achieve near-perfect accuracy on well-regularized models by exploiting "
                "overfitting in hidden layers. Defenses: certified privacy via differential privacy, "
                "DP-SGD training, individual-level rather than membership-level privacy guarantees."
            )
        },
        'serialization': {
            'beginner': (
                "When you save a Python model to a file (pickle), it can contain hidden code. "
                "If someone puts malicious code in a pickle file and you load it, "
                "that code runs on your computer. It's like downloading an executable from the internet - "
                "very dangerous if you don't trust the source."
            ),
            'intermediate': (
                "pickle.load() deserializes Python bytecode and executes arbitrary code via "
                "__reduce__() methods. PyTorch's torch.load() loads pickle files by default. "
                "Attacker-crafted models can steal files, install backdoors, or encrypt data. "
                "Use weights_only=True or JSON/ONNX formats instead."
            ),
            'advanced': (
                "Pickle gadget chains construct RCE via object reduction chains (os.system, etc.). "
                "mitigations: use restricted unpicklers (RestrictedUnpickler), scan bytecode, "
                "validate signatures with cryptographic hashes, use type-safe formats (Protocol Buffers, "
                "FlatBuffers). SafeTensors library prevents RCE by design."
            )
        }
    }
    
    @staticmethod
    def explain_vulnerability(
        vulnerability_type: str,
        level: str = 'beginner'
    ) -> Dict[str, str]:
        """
        Get explanation for vulnerability at specified level
        
        Args:
            vulnerability_type: 'backdoor', 'extraction', 'membership_inference', 'serialization'
            level: 'beginner', 'intermediate', or 'advanced'
        
        Returns:
            Dict with explanation and metadata
        """
        if vulnerability_type not in SecurityExplainer.EXPLANATIONS:
            return {'error': f'Unknown vulnerability type: {vulnerability_type}'}
        
        if level not in ['beginner', 'intermediate', 'advanced']:
            level = 'beginner'
        
        exp = SecurityExplainer.EXPLANATIONS[vulnerability_type][level]
        
        return {
            'type': vulnerability_type,
            'level': level,
            'explanation': exp
        }
    
    @staticmethod
    def get_all_explanations(vulnerability_type: str) -> Dict:
        """Get all explanation levels for a vulnerability"""
        if vulnerability_type not in SecurityExplainer.EXPLANATIONS:
            return {}
        
        return {
            'beginner': SecurityExplainer.EXPLANATIONS[vulnerability_type]['beginner'],
            'intermediate': SecurityExplainer.EXPLANATIONS[vulnerability_type]['intermediate'],
            'advanced': SecurityExplainer.EXPLANATIONS[vulnerability_type]['advanced']
        }
