"""This module contains the detection code for predictable variable
dependence."""
import logging
import re
from copy import copy
from mythril.analysis.issue_annotation import IssueAnnotation
from mythril.analysis.module.base import DetectionModule, EntryPoint
from mythril.analysis.report import Issue
from mythril.exceptions import UnsatError
from mythril.analysis import solver
from mythril.analysis.swc_data import TX_ORIGIN_USAGE
from mythril.laser.ethereum.state.global_state import GlobalState
from mythril.laser.smt import And
from typing import List
from mythril.laser.smt import (
    BVAddNoOverflow,
    BVSubNoUnderflow,
    BVMulNoOverflow,
    BitVec,
    If,
    symbol_factory,
    Not,
    Expression,
    Bool,
    And,
)
from mythril.laser.ethereum.transaction.symbolic import ACTORS
from mythril.laser.smt.bool import And
from mythril.laser.ethereum.transaction.transaction_models import (
    ContractCreationTransaction,
)

import logging

log = logging.getLogger(__name__)



class SenderAnnotation:
    """Symbol Annotation used if a BitVector can overflow"""

    initial_amount = ""
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

class BalanceAnnotation:

    slot = -1
    sourcecode = ""
    
    def __init__(
        self, slot: int, source_code: str
    ) -> None:
        self.slot = slot
        self.sourcecode = source_code
        # self.constraint = constraint
    def update_solt(self, new_solt) -> None:
        self.slot = new_solt
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

class StateOwnerAccessAnnotation:

    index = ""
    constraint = ""

    def __init__(
        self, index, constraint: Bool
    ) -> None:
        self.index = index
        self.constraint = constraint

    def __deepcopy__(self, memodict={}):
        new_annotation = copy(self)
        return new_annotation


class ReceiverAnnotation:
    """Symbol Annotation used if a BitVector can overflow"""
    initial_amount = ""
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
    swc_id = "107"
    description = "This contract might trap your money"
    entry_point = EntryPoint.CALLBACK
    transfer_funcs = ["transferFrom(address,address,uint256)", "transfer(address,uint256)"]
    transfer_sender_func = ["transfer(address,uint256)"]
    transfer_from_func = ["transferFrom(address,address,uint256)"]
    balance_funcs = ["balanceOf(address)"]
    allowance_funcs = ["allowance(address,address)"]

    post_hooks = ["RETURN", "REVERT", "STOP", "CALLER", "CALLDATALOAD",]
    pre_hooks = ["SSTORE", "SLOAD", "CALLDATALOAD", "JUMPI",]
    issues = []
    address_for_calldataload = -1
    slot_for_sload = -1
    source_code_for_sload = ""
   
 
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

        funcs = {
            "SSTORE": [self._handle_sstore],
            "SLOAD": [self._handle_sload],
            "JUMPI": [self._handle_jumpi],
            "CALLER": [self._handle_caller],
            "CALLDATALOAD": [self._handle_calldataload],
            "RETURN": [self._handle_transaction_end],
            "REVERT": [self._handle_transaction_end],
            "STOP": [self._handle_transaction_end],
        }
        results = []
        for func in funcs[opcode]:
            result = func(state)
            if result and len(result) > 0:
                results += result
        return results

    
    def _handle_caller(self, state:GlobalState):
        state.mstate.stack[-1].annotate(OwnerAccessAnnotation(state))
    
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

        if self.address_for_calldataload == -1:
            self.address_for_calldataload = state.mstate.stack[-1]
            return
        elif self.address_for_calldataload == "4":
            state.mstate.stack[-1].annotate(SenderAnnotation(state))
        elif self.address_for_calldataload == "36":
            state.mstate.stack[-1].annotate(ReceiverAnnotation(state))
        elif self.address_for_calldataload == "68":
            state.mstate.stack[-1].annotate(AmountAnnotation(state))
        self.address_for_calldataload = -1
        return
    
    def _handle_sload(self, state: GlobalState):
        index = state.mstate.stack[-1]
        # for annotation in state.annotations:
        #     if isinstance(annotation, StateOwnerAccessAnnotation) and annotation.index == index: 
        if state.environment.active_function_name in self.transfer_funcs: 
            for annotation in state.world_state.annotations:
                if isinstance(annotation, BalanceAnnotation):
                    balance_slot = annotation.slot      
            for annotation in index.annotations:
                if isinstance(annotation, SenderAnnotation) or isinstance(annotation, ReceiverAnnotation):
                    if annotation.init_amount == "" and balance_slot == self._get_slot(str(index)):
                        # if self._get_slot(str(index))
                        annotation.set_init_amount(state.environment.active_account.storage[index])
        elif state.environment.active_function_name in self.balance_funcs:
            if self.slot_for_sload == -1:
                self.slot_for_sload = int(re.findall(r"\d+", str(index))[-1])
                self.source_code_for_sload = state.environment.contract.get_source_info(state.get_current_instruction()["address"], False).code
            else:
                state.mstate.stack[-1].annotate(BalanceAnnotation(slot=self.slot_for_sload, source_code=self.source_code_for_sload))
                self.slot_for_sload = -1
                self.source_code_for_sload = ""
            # print (state.environment.active_account.storage[index].annotations)
        elif state.environment.active_function_name in self.allowance_funcs:
            state.environment.active_account.storage[index].annotate(AllowanceAnnotation(state))

    def _handle_sstore(self, state:GlobalState):
        sstore_value = state.mstate.stack[-2]  
        sstore_key = state.mstate.stack[-1]

        attacker_constraints = []

        for tx in state.world_state.transaction_sequence:
            if not isinstance(tx, ContractCreationTransaction):
                attacker_constraints.append(
                    And(tx.caller == ACTORS.attacker, tx.caller == tx.origin)
                )
        try:  
            constraints = (
                state.world_state.constraints
                + attacker_constraints
            ) 
            transaction_sequence = solver.get_transaction_sequence(
                state, constraints
            )

            if state.environment.active_function_name in self.transfer_funcs:
                for annotation in state.world_state.annotations:
                    if isinstance(annotation, BalanceAnnotation):
                        balance_slot = annotation.slot 
                for annotation in sstore_key.annotations:
                    if isinstance(annotation, SenderAnnotation) or isinstance(annotation, ReceiverAnnotation):
                        if self._get_slot(sstore_key) == balance_slot:
                            annotation.set_fini_amount(sstore_value)

        except UnsatError:
            state.annotate(
                OwnerAccessAnnotation(state)
            )
            log.debug("This storage under the control of owner")

            if state.environment.active_function_name in self.transfer_funcs:
                description = (
                    "The owner-controlled storage variable has been found influence the transfer of ERC20"
                )
                severity = "High"
                

                issue = Issue(
                        contract=state.environment.active_account.contract_name,
                        function_name=state.environment.active_function_name,
                        address=state.get_current_instruction()["address"],
                        swc_id="1111",
                        bytecode=state.environment.code.bytecode,
                        title="Dependence on an owner-controlled variable",
                        severity=severity,
                        description_head="The transfer of token depends on the owner",
                        description_tail=description,
                        gas_used=(state.mstate.min_gas_used, state.mstate.max_gas_used),
                        transaction_sequence=transaction_sequence,
                )
                state.annotate(
                    IssueAnnotation(
                        conditions=[And(*constraints)], issue=issue, detector=self
                    )
                )

                self.issues.append(issue)
                

        for annotation in state.world_state.constraints:
            if isinstance(annotation, OwnerAccessAnnotation):
                sstore_value.annotate(OwnerAccessAnnotation(state))
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

    def _handle_transaction_end(self, state: GlobalState):
        if state.environment.active_function_name in self.balance_funcs:
            for annotation in state.mstate.stack[-1].annotations:
                if isinstance(annotation, BalanceAnnotation):
                    state.world_state.annotate(annotation)
        
        if state.environment.active_function_name in self.transfer_funcs:
            for annotation in state.annotations:
                if isinstance(annotation, SenderAnnotation):
                    sender_amount = annotation.final_amount - annotation.init_amount
                elif isinstance(annotation, ReceiverAnnotation):
                    receiver_amount = annotation.final_amount - annotation.init_amount
                
                amount_constraint = [sender_amount-receiver_amount>0]
                
                try:
                    constraints = (state.world_state.constraints + amount_constraint) 
                    transaction_sequence = solver.get_transaction_sequence(state, constraints)
                    description = ("The amount received by recipent is lower than the one sent by sender")
                    severity = "High"
                    issue = Issue(
                        contract=state.environment.active_account.contract_name,
                        function_name=state.environment.active_function_name,
                        address=state.get_current_instruction()["address"],
                        swc_id="1111",
                        bytecode=state.environment.code.bytecode,
                        title="Dependence on an owner-controlled variable",
                        severity=severity,
                        description_head="The transfer of token depends on the owner",
                        description_tail=description,
                        gas_used=(state.mstate.min_gas_used, state.mstate.max_gas_used),
                        transaction_sequence=transaction_sequence,
                    )
                    state.annotate(
                        IssueAnnotation(
                            conditions=[And(*constraints)], issue=issue, detector=self
                        )
                    )

                except UnsatError:
                    return

detector = FakeTokens()
