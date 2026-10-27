from common.models import RoundState, ALLOWED_TRANSITIONS

class OutOfOrderStateError(Exception):
    def __init__(self, current_state: str, attempted_target: str, message: str = None):
        self.current_state = current_state
        self.attempted_target = attempted_target
        self.message = message or (
            f"Illegal state transition from '{current_state}' to '{attempted_target}'. "
            f"Bayora enforces strict linear progression: "
            f"CREATED -> COMMIT -> LOCK -> EXECUTE -> SEAL -> REVEAL -> VERIFY."
        )
        super().__init__(self.message)


class RoundStateMachine:
    @staticmethod
    def validate_transition(current_state_str: str, target_state: RoundState) -> None:
        """
        Validate that the round can legally transition to target_state.
        Raises OutOfOrderStateError (HTTP 409) if out of order.
        """
        try:
            current_state = RoundState(current_state_str)
        except ValueError:
            raise OutOfOrderStateError(
                current_state=current_state_str,
                attempted_target=target_state.value,
                message=f"Current state '{current_state_str}' is invalid or corrupted."
            )

        if current_state in (RoundState.COMPLETED, RoundState.INVALID):
            raise OutOfOrderStateError(
                current_state=current_state.value,
                attempted_target=target_state.value,
                message=f"Round has already reached terminal state '{current_state.value}'."
            )

        # In verify phase, transition can lead to COMPLETED or INVALID
        if current_state == RoundState.VERIFY and target_state in (RoundState.COMPLETED, RoundState.INVALID):
            return

        expected_next = ALLOWED_TRANSITIONS.get(current_state)
        if expected_next != target_state:
            raise OutOfOrderStateError(
                current_state=current_state.value,
                attempted_target=target_state.value,
                message=(
                    f"Out of order transition: Current state is '{current_state.value}', "
                    f"expected '{expected_next.value if expected_next else 'None'}', "
                    f"but attempted to transition to '{target_state.value}'."
                )
            )

    @staticmethod
    def require_exact_state(current_state_str: str, required_state: RoundState, action_name: str) -> None:
        """
        Ensure the round is currently in the exact required state before an in-state action.
        For example: Commit must happen in COMMIT state; Reveal must happen in REVEAL state.
        Raises OutOfOrderStateError (HTTP 409) if the round is not in the required state.
        """
        if current_state_str != required_state.value:
            raise OutOfOrderStateError(
                current_state=current_state_str,
                attempted_target=required_state.value,
                message=(
                    f"Action '{action_name}' requires round state '{required_state.value}', "
                    f"but round is currently in state '{current_state_str}'."
                )
            )
