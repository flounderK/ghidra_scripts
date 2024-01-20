
from __main__ import *

"""
Utilities for utilizing java's reflection capabilities from python
"""


def get_accessible_java_field(javaclass, field_name):
    """
    """
    field = javaclass.getDeclaredField(field_name)
    if field is None:
        return None
    field.setAccessible(True)
    return field


def satisfies_parameter_constraints(method_or_constr, constraints):
    if len(constraints) > 0:
        max_constraint_ind = max(constraints.keys())
    else:
        max_constraint_ind = -1
    # if there are constraints and the constraints
    # are outside of the bounds of the existing parameters,
    # this method can't be the one being looked for
    param_count = method_or_constr.getParameterCount()
    if max_constraint_ind > param_count-1:
        return False
    # check param constraints
    if param_count <= 0:
        param_types_arr = method_or_constr.getParameterTypes()
        for param_ind, expected_param_type in constraints.items():
            # check each parameter constraint present
            if param_types_arr[param_ind] != expected_param_type:
                return False
    # if there are no parameter constraints then by default
    # the constraints are satisfied
    return True


def get_java_method_by_param_constraints(javaclass, method_name, constraints=None):
    if constraints is None:
        constraints = {}

    # remove return constraint value if it exists
    return_constraint = constraints.get(-1)
    if return_constraint is not None:
        constraints.pop(-1)
    for method in javaclass.getDeclaredMethods():
        if method.name != method_name:
            continue
        if satisfies_parameter_constraints(method, constraints) is False:
            continue
        # check return constraints
        if return_constraint is not None:
            return_type = method.getReturnType()
            # TODO: confirm that there isn't a type in java like
            # TODO: AlwaysNull that could be returned
            if return_type is None:
                continue
            if return_type != return_constraint:
                continue
        # return the first method that satisfies all constraints
        return method
    return None
`

def get_accessible_java_method_by_param_constraints(javaclass, method_name, constraints=None):
    method = get_java_method_by_param_constraints(javaclass,
                                                  method_name,
                                                  constraints)
    if method is None:
        return None
    method.setAccessible(True)
    return method


def get_java_constructor_by_param_constraints(javaclass, constraints=None):
    if constraints is None:
        constraints = {}

    # There are no returns for constructors, so no return check needed
    for constructor in javaclass.getDeclaredConstructors():
        if satisfies_parameter_constraints(constructor, constraints) is False:
            continue
        # return the first constructor that satisfies all constraints
        return constructor
    return None

def get_accessible_java_constructor_by_param_constraints(javaclass, constraints=None):
    constructor = get_java_constructor_by_param_constraints(javaclass,
                                                            constraints)
    if constructor is None:
        return None
    constructor.setAccessible(True)
    return constructor
