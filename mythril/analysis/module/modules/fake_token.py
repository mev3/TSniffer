"""This module contains the detection code for predictable variable
dependence."""
import logging
import re
from copy import copy
from mythril.analysis.issue_annotation import IssueAnnotation
from mythril.laser.ethereum.state.annotation import StateAnnotation
from mythril.solidity.soliditycontract import SolidityContract
from mythril.analysis.module.base import DetectionModule, EntryPoint
from mythril.laser.plugin.plugins.plugin_annotations import MutationAnnotation
from mythril.analysis.report import Issue
from mythril.exceptions import UnsatError
from mythril.analysis import solver
from mythril.analysis.swc_data import TX_ORIGIN_USAGE
from mythril.laser.ethereum.state.global_state import GlobalState
from mythril.laser.smt import And
from typing import List
from copy import deepcopy
from z3 import Model, unsat, unknown
from z3.z3types import Z3Exception
from mythril.laser.smt import (
    BVAddNoOverflow,
    BVSubNoUnderflow,
    BVMulNoOverflow,
    simplify,
    UGT,
    ULT,
    BitVec,
    If,
    symbol_factory,
    Not,
    Expression,
    Bool,
    And,
    Solver,
)
from mythril.laser.ethereum.transaction.symbolic import ACTORS
from mythril.laser.smt.bool import And
from mythril.laser.ethereum.transaction.transaction_models import (
    ContractCreationTransaction,
)

import logging

log = logging.getLogger(__name__)


class OwnerBalanceAnnotation:   
    def __init__(
        self, slot:int
    ) -> None:
        self.slot = slot

    def __deepcopy__(self, memodict={}):
        new_annotation = copy(self)
        return new_annotation



class StateSenderReceiverAnnotation(StateAnnotation):

    sender_init_amount = ""
    sender_final_amount = ""
    receiver_init_amount = ""
    receiver_final_amount = ""
    update_to_address= -1
    
    def __init__(
        self
    ) -> None:
        return
        # self.init_amount = init_amount
        # self.constraint = constraint
    def set_sender_final_amount(self, final_amount) -> None:
        self.sender_final_amount = final_amount
    
    def set_sender_init_amount(self, init_amount) -> None:
        self.sender_init_amount = init_amount   

    def set_receiver_final_amount(self, final_amount) -> None:
        self.receiver_final_amount = final_amount

    def set_receiver_init_amount(self, init_amount) -> None:
        self.receiver_init_amount = init_amount

    def set_update_to_address(self, address) -> None:
        self.update_to_address = address

    def __copy__(self):
        result = StateSenderReceiverAnnotation()
        result.sender_final_amount = self.sender_final_amount
        result.receiver_final_amount = self.receiver_final_amount
        result.sender_init_amount = self.sender_init_amount
        result.receiver_init_amount = self.receiver_init_amount
        result.update_to_address = self.update_to_address
        return result 

       


class SenderAnnotation:
    """Symbol Annotation used if a BitVector can overflow"""

    init_amount = ""
    final_amount = ""
    
    def __init__(
        self, sender_state: GlobalState
    ) -> None:
        self.sender_state = sender_state

    def __deepcopy__(self, memodict={}):
        new_annotation = copy(self)
        return new_annotation

    def set_init_amount(self, amount):
        self.init_amount = amount
    
    def set_fini_amount(self, amount):
        self.final_amount = amount


class OwnerAccessAnnotation:

    def __init__(
        self, sender_state: GlobalState
    ) -> None:
        self.sender_state = sender_state
        # self.constraint = constraint

    def __deepcopy__(self, memodict={}):
        new_annotation = copy(self)
        return new_annotation


class BalanceAnnotation(StateAnnotation):

    slot = -1
    sourcecode = ""
    
    def __init__(
        self, slot: int, sourcecode: str
    ) -> None:
        self.slot = slot
        self.sourcecode = sourcecode
        # self.constraint = constraint
    def update_solt(self, new_solt) -> None:
        self.slot = new_solt
       
    def __copy__(self):
        result = BalanceAnnotation(self.slot, self.sourcecode)
        return result 
    
    @property
    def persist_to_world_state(self) -> bool:
        return True

    @property
    def persist_over_calls(self) -> bool:
        return True

class SlotAnnotation:
    def __init__(
        self, slot: int
    ) -> None:
        self.slot = slot
        # self.constraint = constraint

    def __deepcopy__(self, memodict={}):
        new_annotation = copy(self)
        return new_annotation
       

class AllowanceAnnotation:

    def __init__(
        self, sender_state: GlobalState
    ) -> None:
        self.sender_state = sender_state
        # self.constraint = constraint

    def __deepcopy__(self, memodict={}):
        new_annotation = copy(self)
        return new_annotation


class ArbitraryUserAccessBalanceAnnotation(StateAnnotation):
    def __init__(
        self, address
    ) -> None:
        self.address = address
    
    def __copy__(self):
        result = ArbitraryUserAccessBalanceAnnotation(self.address)
        return result 
    
    @property
    def persist_to_world_state(self) -> bool:
        return True

    @property
    def persist_over_calls(self) -> bool:
        return True


class StateOwnerAccessAnnotation(StateAnnotation):

    def __init__(
        self, slot
    ) -> None:
        self.slot = slot
    
    def __copy__(self):
        result = StateOwnerAccessAnnotation(self.slot)
        return result 
    
    @property
    def persist_to_world_state(self) -> bool:
        return True

    @property
    def persist_over_calls(self) -> bool:
        return True

class ReceiverAnnotation:
    """Symbol Annotation used if a BitVector can overflow"""
    init_amount = ""
    final_amount = ""
    
    def __init__(
        self, receiver_state: GlobalState
    ) -> None:
        self.receiver_state = receiver_state


    def __deepcopy__(self, memodict={}):
        new_annotation = copy(self)
        return new_annotation

    def set_init_amount(self, amount):
        self.init_amount = amount
    
    def set_fini_amount(self, amount):
        self.final_amount = amount

class AmountAnnotation:
    """Symbol Annotation used if a BitVector can overflow"""

    def __init__(
        self, amount_state, amount
    ) -> None:
        self.amount_state = amount_state
        self.amount = amount

    def __deepcopy__(self, memodict={}):
        new_annotation = copy(self)
        return new_annotation


class FakeTokens(DetectionModule):
    """This module searches for low level calls (e.g. call.value()) that
    forward all gas to the callee."""

    name = "Find fake token"
    swc_id_owner_control = "120"
    swc_id_balance_amount = "121"
    description = "This contract might trap your money"
    entry_point = EntryPoint.CALLBACK
    transfer_funcs = ["transferFrom(address,address,uint256)", "transfer(address,uint256)"]
    transfer_funcs_sigs = ["0x23b872dd", "0xa9059cbb"]
    transfer_sender_func = ["transfer(address,uint256)"]
    transfer_sender_func_sig = ["0xa9059cbb"]
    transfer_from_func = ["transferFrom(address,address,uint256)"]
    transfer_from_func_sig = ["0x23b872dd"]
    balance_funcs = ["balanceOf(address)"]
    balance_funcs_sig = ["0x70a08231"]
    allowance_funcs = ["allowance(address,address)"]
    allowance_funcs_sig = ["0xdd62ed3e"]
    global_balance_solt = -1

    post_hooks = ["CALLER", "CALLDATALOAD", "SLOAD",]
    pre_hooks = ["SSTORE", "SLOAD", "CALLDATALOAD", "RETURN", "REVERT", "STOP",]
    issues = []
    address_for_calldataload = -1
    slot_for_sload = -1
    slot_for_sload_common = -1
    bool_for_sload_transfer_func = False
    source_code_for_sload = ""
    bool_post = False
   
    def update_global_balance(self, num):
        self.global_balance_solt = num


    def _update_arbitrary_annotation(self, annotations, address, state:GlobalState) -> None:
        for annotation in annotations:
            if isinstance(annotation, ArbitraryUserAccessBalanceAnnotation):
                if annotation.address == address:
                    return
        state.annotate(ArbitraryUserAccessBalanceAnnotation(address=address))

    
    def _updateIssues(self, annotations) -> None:
        _arbitrary_issues = []
        for annotation in annotations:
            if isinstance(annotation, ArbitraryUserAccessBalanceAnnotation):
                if not annotation.address in _arbitrary_issues:
                    _arbitrary_issues.append(annotation.address)

        for issue in self.issues:
            if issue.swc_id == self.swc_id_owner_control:
                if issue.address in _arbitrary_issues:
                    self.issues.remove(issue)
        return
    
    def _execute(self, state: GlobalState) -> None:
        """

        :param state:
        :return:
        """

        self._analyze_state(state)

        # annotation = get_potential_issues_annotation(state)
        # annotation.potential_issues.extend(potential_issues)
    
    def _get_slot(self, index):
        return int(re.findall(r"\d+", str(index))[-1])

    def _is_constructor(self, function_summary):
        return "Constructor" in function_summary

    def _analyze_state(self, state: GlobalState):
        """

        :param state:  
        :return:
        """

        opcode = state.get_current_instruction()["opcode"]
        if opcode not in self.pre_hooks and opcode not in self.post_hooks:
            opcode = state.environment.code.instruction_list[state.mstate.pc - 1]['opcode']
            if opcode not in self.post_hooks:
                return
            else:
                self.bool_post = True
        # print("Current Function Name:")
        # print(state.environment.active_function_name)
        # print("\n")
        funcs = {
            "SSTORE": [self._handle_sstore],
            "SLOAD": [self._handle_sload],
            "JUMPI": [self._handle_jumpi],
            "CALLER": [self._handle_caller],
            "CALLDATALOAD": [self._handle_calldataload],
            "RETURN": [self._handle_transaction_end],
            "REVERT": [self._handle_transaction_end],
            "STOP": [self._handle_transaction_end],
            # "MSTORE": [self._handle_mstore],
            # "MSTORE8": [self._handle_mstore],
        }
        results = []
        for func in funcs[opcode]:
            result = func(state)
            if result and len(result) > 0:
                results += result
        self.bool_post = False
        self._updateIssues(state.annotations)
        
        # return results

    
    def _handle_caller(self, state:GlobalState):
        state.mstate.stack[-1].annotate(OwnerAccessAnnotation(state))
        if state.environment.active_function_name in self.transfer_sender_func or state.environment.active_function_hash in self.transfer_sender_func_sig:
            state.mstate.stack[-1].annotate(SenderAnnotation(state))
    
    def _handle_jumpi(self, state:GlobalState):
        # for annotation in state.mstate.stack[-1].annotations:
        #     if isinstance(annotation, OwnerAccessAnnotation):
        #         state.world_state.constraints.annote(OwnerAccessAnnotation())
        return

    # def _handle_non_transfer_sstore(self, state:GlobalState):
    #     sstore_value = state.stack[-2]

    #     for annotation in state.world_state.constraints.__annotations__:
    #         if isinstance(annotation, OwnerAccessAnnotation):
    #             sstore_value.annotate(OwnerAccessAnnotation())       
    #     return




    def _handle_calldataload(self, state:GlobalState):
        if state.environment.active_function_name in self.transfer_funcs or state.environment.active_function_hash in self.transfer_funcs_sigs:
            if self.address_for_calldataload == -1:
                self.address_for_calldataload = state.mstate.stack[-1]
                return
            else:
                if state.environment.active_function_name in self.transfer_from_func or state.environment.active_function_hash in self.transfer_from_func_sig:
                    if self.address_for_calldataload == "4":
                        state.mstate.stack[-1].annotate(SenderAnnotation(state))
                    elif self.address_for_calldataload == "36":
                        # print("receiver here1")
                        state.mstate.stack[-1].annotate(ReceiverAnnotation(state))
                if state.environment.active_function_name in self.transfer_sender_func or state.environment.active_function_hash in self.transfer_sender_func_sig:
                    if self.address_for_calldataload == "4":
                        # print("receiver here2")
                        state.mstate.stack[-1].annotate(ReceiverAnnotation(state))
                self.address_for_calldataload = -1
        else:
            return
    
    def _handle_sload(self, state: GlobalState):
        index = state.mstate.stack[-1]

        if not self.bool_post:
            self.slot_for_sload_common = self._get_slot(str(index))
        else:
            state.mstate.stack[-1].annotate(SlotAnnotation(self.slot_for_sload_common))
        # for annotation in state.annotations:
        #     if isinstance(annotation, StateOwnerAccessAnnotation) and annotation.index == index: 
        if state.environment.active_function_name in self.transfer_funcs or state.environment.active_function_hash in self.transfer_funcs_sigs: 
            # print ("111111111")
            # print(state.environment.active_function_name)
            sender_receiver_annotation = StateSenderReceiverAnnotation()
            pre_exist_sender_receiver_annotation = False
            for state_annotation in state.annotations:
                if isinstance(state_annotation, StateSenderReceiverAnnotation):
                    pre_exist_sender_receiver_annotation = True
                    sender_receiver_annotation = state_annotation
            if not pre_exist_sender_receiver_annotation:
                state.annotate(sender_receiver_annotation)

            if not self.bool_for_sload_transfer_func:
                balance_slot = ""
                for annotation in state.world_state.annotations:
                    if isinstance(annotation, BalanceAnnotation):
                        # print ("3333333333")
                        balance_slot = annotation.slot
                
                # for test
                if balance_slot == "" and self.global_balance_solt != -1:
                    # print("laji")
                    balance_slot = self.global_balance_solt
                for annotation in index.annotations:
                    if isinstance(annotation, SenderAnnotation) or isinstance(annotation, ReceiverAnnotation):
                        if annotation.init_amount == "" and balance_slot!= "" and balance_slot == self._get_slot(str(index)):
                            # if self._get_slot(str(index))
                            # print ("44444444444")
                            annotation.set_init_amount(state.environment.active_account.storage[index])
                            if isinstance(annotation, SenderAnnotation):
                                sender_receiver_annotation.set_sender_init_amount(state.environment.active_account.storage[index])
                            else:
                                # print("receiver here3")
                                sender_receiver_annotation.set_receiver_init_amount(state.environment.active_account.storage[index])
                self.bool_for_sload_transfer_func = True
            else:
                self.bool_for_sload_transfer_func = False
        elif state.environment.active_function_name in self.balance_funcs or state.environment.active_function_hash in self.balance_funcs_sig: 
            if self.slot_for_sload == -1:
                # print ("hhhhhhhh")
                state.annotate(MutationAnnotation())
                self.slot_for_sload = int(re.findall(r"\d+", str(index))[-1])
                if isinstance(state.environment.contract, SolidityContract):
                    self.source_code_for_sload = state.environment.contract.get_source_info(state.get_current_instruction()["address"], False).code
            else:
                # print ("mmmmmmmm")

                #  For Test
                self.update_global_balance(self.slot_for_sload)

                state.annotate(MutationAnnotation())
                state.mstate.stack[-1].annotate(BalanceAnnotation(slot=self.slot_for_sload, sourcecode=self.source_code_for_sload))

                state.annotate(BalanceAnnotation(slot=self.slot_for_sload, sourcecode=self.source_code_for_sload))
                state.world_state.annotate(MutationAnnotation())
                state.world_state.annotate(BalanceAnnotation(slot=self.slot_for_sload, sourcecode=self.source_code_for_sload))
                self.slot_for_sload = -1
                self.source_code_for_sload = ""
            # print (state.environment.active_account.storage[index].annotations)
        # elif state.environment.active_function_name in self.allowance_funcs:
        #     state.environment.active_account.storage[index].annotate(AllowanceAnnotation(state))

    def _handle_sstore(self, state:GlobalState):
        sstore_value = state.mstate.stack[-2]  
        sstore_key = state.mstate.stack[-1]

        attacker_constraints = []
        balance_slot = ""

        if self._is_constructor(state.environment.active_function_name):
            return
        
        if not (state.environment.active_function_name in self.transfer_funcs or state.environment.active_function_hash in self.transfer_funcs_sigs):
                # print("8888888") 
                return
        
        is_balance = False
        if sstore_key.symbolic:
            for annotation in state.world_state.annotations:
                if isinstance(annotation, BalanceAnnotation):
                    if self._get_slot(sstore_key) == annotation.slot:
                        is_balance = True
            # for test
            if  self._get_slot(sstore_key) == self.global_balance_solt:
                is_balance = True
        
        if is_balance == False:
            return
               
        # for annotation in sstore_key.annotations:
        #     if isinstance(annotation, OwnerBalanceAnnotation):
        #         print ("888888")
        
        attacker_constraints.append(And(state.world_state.transaction_sequence[-1].caller == ACTORS.attacker, state.world_state.transaction_sequence[-1].caller == state.world_state.transaction_sequence[-1].origin))
        # for tx in state.world_state.transaction_sequence:
        #     if not isinstance(tx, ContractCreationTransaction):
        #         attacker_constraints.append(
        #             And(tx.caller == ACTORS.attacker, tx.caller == tx.origin)
        #         )
            
        constraints = copy(state.world_state.constraints)
        constraints += attacker_constraints

        # if not (state.environment.active_function_name in self.transfer_funcs):
        #     # if self._get_slot(sstore_key) == balance_slot:
        #     #     print("8888888") 
        #     return
        


        try:
            solver.get_model(constraints)
            #print("The balances in transfer does not under the control of owner")
            #print("The address of this instruction is" + str(state.get_current_instruction()["address"]))
            self._update_arbitrary_annotation(state.annotations, state.get_current_instruction()["address"], state)
            
            # state.annotate(ArbitraryUserAccessBalanceAnnotation(state.get_current_instruction()["address"]))
            # constraints = (
            #     state.world_state.constraints
            #     + attacker_constraints 
            # ) 
            # transaction_sequence = solver.get_transaction_sequence(
            #     state, constraints
            # )  

            sender_receiver_annotation = StateSenderReceiverAnnotation()
            pre_exist_sender_receiver_annotation = False
            for state_annotation in state.annotations:
                if isinstance(state_annotation, StateSenderReceiverAnnotation):
                    pre_exist_sender_receiver_annotation = True
                    sender_receiver_annotation = state_annotation
            if not pre_exist_sender_receiver_annotation:
                state.annotate(sender_receiver_annotation)

            for annotation in state.world_state.annotations:
                if isinstance(annotation, BalanceAnnotation):
                    balance_slot = annotation.slot 
            # For test
            if balance_slot == "" and self.global_balance_solt!= -1 :
                balance_slot = self.global_balance_solt

            for annotation in sstore_key.annotations:
                if isinstance(annotation, SenderAnnotation) or isinstance(annotation, ReceiverAnnotation):
                    if balance_slot != "" and self._get_slot(sstore_key) == balance_slot:
                        annotation.set_fini_amount(sstore_value)
                        if isinstance(annotation, SenderAnnotation):
                            sender_receiver_annotation.set_sender_final_amount(sstore_value)
                        else:
                            sender_receiver_annotation.set_receiver_final_amount(sstore_value)
                            sender_receiver_annotation.set_update_to_address(state.get_current_instruction()["address"])

        except UnsatError:
            # print("The storage in transfer is updated by owner")
            # print(constraints)
            state.annotate(StateOwnerAccessAnnotation(sstore_key))
            log.debug("This storage under the control of owner")
            if sstore_key.symbolic:
                for annotation in state.world_state.annotations:
                    if isinstance(annotation, BalanceAnnotation):
                        if self._get_slot(sstore_key) == annotation.slot:
                            print("The balances of transfer is updated by owner")
                            # print("The address of this instruction is" + str(state.get_current_instruction()["address"]))

                # for test
                if self._get_slot(sstore_key) == self.global_balance_solt:
                    print("The balances of transfer is updated by owner")
                    # print("The address of this instruction is" + str(state.get_current_instruction()["address"]))

            if state.environment.active_function_name in self.transfer_funcs or state.environment.active_function_hash in self.transfer_funcs_sigs:
                description = (
                    "Owner-controlled storage variables have been found to affect ERC20 transfers"
                )
                severity = "High"
                

                issue = Issue(
                        contract=state.environment.active_account.contract_name,
                        function_name=state.environment.active_function_name,
                        address=state.get_current_instruction()["address"],
                        swc_id=self.swc_id_owner_control,
                        bytecode=state.environment.code.bytecode,
                        title="Dependence on an owner-controlled variable",
                        severity=severity,
                        description_head="The transfer of token depends on the owner",
                        description_tail=description,
                        transaction_sequence= None,
                        gas_used=(state.mstate.min_gas_used, state.mstate.max_gas_used),
                )
                state.annotate(
                    IssueAnnotation(
                        conditions=[And(*constraints)], issue=issue, detector=self
                    )
                )

                self.issues.append(issue)
                

        # for annotation in state.world_state.constraints:
        #     if isinstance(annotation, OwnerAccessAnnotation):
        #         sstore_value.annotate(OwnerAccessAnnotation(state))
        # if  state.environment.active_function_name in self.transfer_funcs:
        #     for annotation in state.constraints.__annotations__:
        #         if isinstance(annotation, OwnerAccessAnnotation):
        #             return
                #     constraints = copy(state.world_state.constraints)
                # try:
                #     transaction_sequence = solver.get_transaction_sequence(state, constraints)
                # except UnsatError:
                #     continue
                # description = (
                #     "The owner-controlled storage variable has been found influence the transfer of ERC20"
                # )
                # severity = "High"

                # issue = Issue(
                #         contract=state.environment.active_account.contract_name,
                #         function_name=state.environment.active_function_name,
                #         address=state.get_current_instruction()["address"],
                #         swc_id="1111",
                #         bytecode=state.environment.code.bytecode,
                #         title="Dependence on an owner-controlled variable",
                #         severity=severity,
                #         description_head="The transfer of token depends on the owner",
                #         description_tail=description,
                #         gas_used=(state.mstate.min_gas_used, state.mstate.max_gas_used),
                #         transaction_sequence=transaction_sequence,
                # )
                # state.annotate(
                #     IssueAnnotation(
                #         conditions=[And(*constraints)], issue=issue, detector=self
                #     )
                # )

                # self.issues.append(issue)
                # else: 
                #     for annotation in sstore_key.annotations:
                #         if isinstance(annotation, SenderAnnotation) or isinstance(annotation, ReceiverAnnotation):
                #             annotation.set_fini_amount(sstore_value)
                    
        # for annotation in state.stack[-2].annotations: 
        #     if isinstance(annotation, SenderAnnotation):
        #     #  state.world_state. 
        #         return
        #     if isinstance(annotation, ReceiverAnnotation):
        #         return

    # def _handle_mstore(self, state: GlobalState):
    #     if state.environment.active_function_name in self.balance_funcs or state.environment.active_function_hash in self.balance_funcs_sig:
    #         _tmp_balance_annotation = ""
    #         for annotation in state.mstate.stack[-2].annotations:
    #             if isinstance(annotation, BalanceAnnotation):
    #                 _tmp_balance_annotation = annotation
    #         if _tmp_balance_annotation != "":
    #             for annotation in state.annotations:
    #                 if isinstance(annotation, BalanceAnnotation) and _tmp_balance_annotation != "":
    #                     BalanceAnnotation.update_solt(_tmp_balance_annotation.slot)
    #                     return
    #             state.annotate(_tmp_balance_annotation)
    
    def _handle_transaction_end(self, state: GlobalState):
        
        sender_amount = ""
        receiver_amount = ""
        if state.environment.active_function_name in self.transfer_funcs or state.environment.active_function_hash in self.transfer_funcs_sigs:
            for state_annotation in state.annotations:
                if isinstance(state_annotation, StateSenderReceiverAnnotation) and isinstance(state_annotation.sender_init_amount, BitVec) and isinstance(state_annotation.sender_final_amount, BitVec) and isinstance(state_annotation.receiver_init_amount, BitVec) and isinstance(state_annotation.receiver_final_amount, BitVec):
                    # sender_amount = simplify(state_annotation.sender_final_amount - state_annotation.sender_init_amount)
                    # receiver_amount = simplify(state_annotation.receiver_final_amount - state_annotation.receiver_init_amount)
                # if isinstance(sender_amount, BitVec) and isinstance(receiver_amount, BitVec):
                    amount_constraint = ULT(simplify(state_annotation.sender_final_amount + (state_annotation.receiver_final_amount - state_annotation.receiver_init_amount)), state_annotation.sender_init_amount)
                    s = Solver()
                    s.set_timeout(20000)
                    s.add(simplify(amount_constraint))
                    result = s.check()
                    # delete unknown
                    if result == unsat:
                        # print("666666666")
                        break
                    # print("The amount received by recipent is lower than the one sent by sender 1")

                    # try:
                    #     constraints = (state.world_state.constraints + [amount_constraint]) 
                    #     transaction_sequence = solver.get_transaction_sequence(state, constraints)
                    description = ("Sent more tokens than received")
                    severity = "High"
                    issue = Issue(
                        contract=state.environment.active_account.contract_name,
                        function_name=state.environment.active_function_name,
                        address=state_annotation.update_to_address,
                        swc_id=self.swc_id_balance_amount,
                        bytecode=state.environment.code.bytecode,
                        title="Charging token fee ",
                        severity=severity,    
                        description_head="Sent more tokens than received",
                        description_tail=description,
                        gas_used=(state.mstate.min_gas_used, state.mstate.max_gas_used),
                        
                    )
                    # state.annotate(
                    #     IssueAnnotation(
                    #         conditions=[And(*amount_constraint)], issue=issue, detector=self
                    #     )
                    # )

                    self.issues.append(issue)


detector = FakeTokens()
