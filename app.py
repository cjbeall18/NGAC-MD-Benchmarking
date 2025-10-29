from flask import Flask, session, request, render_template, redirect, url_for
from pymongo import MongoClient, monitoring
from functools import wraps  #could not find version for
import urllib.parse
import hashlib #could not find version for
import grpc 
from v1 import cmd_pb2
from v1 import pdp_adjudication_pb2
from v1 import pdp_adjudication_pb2_grpc
from v1 import pdp_query_pb2_grpc
from v1 import pdp_query_pb2
import os #could not find version for
import time #could not find version for
import json #could not find version for


app = Flask(__name__)
app.config["SECRET_KEY"] = os.urandom(24)

CommandLogging = {
    "CurrentCommand": None
}

ObjectAttributeIDs = {
    "Benefits": None,
    "Departments": None,
    "Employees": None,
    "Orders": None,
    "Payroll": None,
    "Positions": None,
    "Products": None,
    "Public_Profile_Fields": None
}

ObjectIDs = {

}


UserAttributeIDs = {

}

UserIDs = {

}

class CommandLogger(monitoring.CommandListener):
    def started(self, event):
        CommandCopy = event.command.copy()
        CommandCopy.pop('$db', None)
        CommandCopy.pop('$readPreference', None)
        CommandCopy.pop('lsid', None)
        CommandCopy.pop('$clusterTime', None)
        CommandCopy.pop('txnNumber', None)
        CommandCopy.pop('startTransaction', None)
        CommandCopy.pop('autocommit', None)
        CommandCopy.pop('readConcern', None)
        CommandCopy.pop('limit', None)
        CommandCopy.pop('singleBatch', None)
        CommandLogging["CurrentCommand"] = CommandCopy

      
    def succeeded(self, event):
        pass
    
    def failed(self, event):
        pass

monitoring.register(CommandLogger())


def GetFieldNames(Collection):
    FieldNames = set()
    FullCollection = Collection.find()
    for Doccument in FullCollection:
        for key in Doccument.keys():
            if key != "_id":
                FieldNames.add(str(key))
    return FieldNames

def GetKeyByValue(value):
    for key, val in ObjectIDs.items():
        if val == value:
            return key
    return None

def CreateSuperUserWithPml():
    channel = grpc.insecure_channel('localhost:50052')
    metadata = grpc.aio.Metadata(('x-pm-user', 'super'), ('x-pm-attrs', '2'))
    adminStub = pdp_adjudication_pb2_grpc.AdminAdjudicationServiceStub(channel)
    
    PMLContent = """
        create UA "@super" in [PM_ADMIN_PC]
        assign "super" to ["@super"]
        associate "@super" and PM_ADMIN_BASE_OA with ["*a"]
        """
    
    PMLCommand = cmd_pb2.AdminCommand(
        execute_pml_cmd=cmd_pb2.ExecutePMLCmd(pml=PMLContent)
    )
    
    response = adminStub.AdjudicateAdminCmd(
        pdp_adjudication_pb2.AdminCmdRequest(commands=[PMLCommand]),
        metadata=metadata
    )
    
def CheckAppUserProhibition(username, operation, userAttributeID, PublicProfileFieldsOAID):
    """Check if user has permission on Public_Profile_Fields OA and return all allowed objects"""
    channel = grpc.insecure_channel('localhost:50052')
    query_stub = pdp_query_pb2_grpc.PolicyQueryServiceStub(channel)
    metadata = grpc.aio.Metadata(('x-pm-user', username), ('x-pm-attrs', str(userAttributeID)))
    
    ListOfAllowed = []
    
    try:
        # First, check if user has the operation permission on the Public_Profile_Fields OA itself
        target_ctx = pdp_query_pb2.TargetContext()
        target_ctx.id = PublicProfileFieldsOAID
        
        response = query_stub.SelfComputePrivileges(
            target_ctx,
            metadata=metadata,
            timeout=30
        )
        
        hasPermissionOnOA = operation in response.values
        
        if hasPermissionOnOA:
            # If user has permission on the OA, they have permission on ALL its descendants, 
            # so execute graph query as superuser to provide list of allowed objects because App user cannot query graph
            metadata = grpc.aio.Metadata(('x-pm-user', 'super'), ('x-pm-attrs', '2'))
            
            query = pdp_query_pb2.GetAdjacentAssignmentsQuery(node_id=PublicProfileFieldsOAID)
            descendants_response = query_stub.GetAdjacentAscendants(query, metadata=metadata, timeout=30)

            for node in descendants_response.nodes:
                if node.type == 4:  # Object (O) type
                    ListOfAllowed.append(node.id)
            
    except grpc.RpcError as e:
        print(f"Error checking permissions: {e}")
    
    return ListOfAllowed

def CheckUserProhibition(username, FieldIDsList, operation, userOAID):
    """Check what prohibitions a user has"""
    channel = grpc.insecure_channel('localhost:50052')
    query_stub = pdp_query_pb2_grpc.PolicyQueryServiceStub(channel)
    metadata = grpc.aio.Metadata(('x-pm-user', username), ('x-pm-attrs', str(userOAID)))
    ListOfAllowed = []
    for fieldID in FieldIDsList:
        target_ctx = pdp_query_pb2.TargetContext()
        target_ctx.id = fieldID
        
        response = query_stub.SelfComputePrivileges(
            target_ctx,
            metadata=metadata,
            timeout=30
        )
        
        hasPermission = operation in response.values
        if hasPermission == True:
            ListOfAllowed.append(fieldID)
    return ListOfAllowed

    
def CheckUserPermissions(username, operation, userAttributeID, ObjectAttributeID):
    """Check if user has permission on any given OA and return all allowed objects"""
    channel = grpc.insecure_channel('localhost:50052')
    query_stub = pdp_query_pb2_grpc.PolicyQueryServiceStub(channel)
    metadata = grpc.aio.Metadata(('x-pm-user', username), ('x-pm-attrs', str(userAttributeID)))
    
    ListOfAllowed = []
    
    try:
        # First, check if user has the operation permission on the Public_Profile_Fields OA itself
        target_ctx = pdp_query_pb2.TargetContext()
        target_ctx.id = ObjectAttributeID
        
        response = query_stub.SelfComputePrivileges(
            target_ctx,
            metadata=metadata,
            timeout=30
        )

        # execute graph query as superuser to provide list of objects for a given OA because not all users can query adjacent nodes
        metadata = grpc.aio.Metadata(('x-pm-user', 'super'), ('x-pm-attrs', '2'))
        query = pdp_query_pb2.GetAdjacentAssignmentsQuery(node_id=ObjectAttributeID)
        descendants_response = query_stub.GetAdjacentAscendants(query, metadata=metadata, timeout=30)

        # swap back to metadata for user we are checking permissions for
        metadata = grpc.aio.Metadata(('x-pm-user', username), ('x-pm-attrs', str(userAttributeID)))
        for node in descendants_response.nodes:
            if node.type == 4:  # 4 is Object (O) type
                target_ctx = pdp_query_pb2.TargetContext()
                target_ctx.id = node.id
                
                response = query_stub.SelfComputePrivileges(
                    target_ctx,
                    metadata=metadata,
                    timeout=30
                )
                
                hasPermission = operation in response.values
                if hasPermission == True:
                    ListOfAllowed.append(node.id)
            
    except grpc.RpcError as e:
        print(f"Error checking permissions: {e}")
    
    return ListOfAllowed

def CheckUserProhibition(username, FieldIDsList, operation, userOAID):
    """Check what prohibitions a user has"""
    channel = grpc.insecure_channel('localhost:50052')
    query_stub = pdp_query_pb2_grpc.PolicyQueryServiceStub(channel)
    metadata = grpc.aio.Metadata(('x-pm-user', username), ('x-pm-attrs', str(userOAID)))
    ListOfAllowed = []
    for fieldID in FieldIDsList:
        target_ctx = pdp_query_pb2.TargetContext()
        target_ctx.id = fieldID
        
        response = query_stub.SelfComputePrivileges(
            target_ctx,
            metadata=metadata,
            timeout=30
        )
        
        hasPermission = operation in response.values
        if hasPermission == True:
            ListOfAllowed.append(fieldID)
    return ListOfAllowed

def InitalizeGraph():
    channel = grpc.insecure_channel('localhost:50052')
    metadata = grpc.aio.Metadata(('x-pm-user', 'super'), ('x-pm-attrs', '2'))

    adminStub = pdp_adjudication_pb2_grpc.AdminAdjudicationServiceStub(channel)

    collections = [
        "CUSTOMER",
        "DISTRICT",
        "HISTORY",
        "ITEM",
        "NEW_ORDER",
        "ORDERS",
        "STOCK",
        "WAREHOUSE"
    ]
    print("Initalizing Graph, see docker container logs for details...")
    # Create school policy class

    StartTime = time.perf_counter()
    CreatePolicyClass = cmd_pb2.AdminCommand(
        create_policy_class_cmd=cmd_pb2.CreatePolicyClassCmd(name="TPCC")
    )
    response = adminStub.AdjudicateAdminCmd(
        pdp_adjudication_pb2.AdminCmdRequest(commands=[CreatePolicyClass]),
        metadata=metadata
    )
    EndTime = time.perf_counter()
    print(f"It took {EndTime - StartTime:0.4f} seconds to create the TPCC policy class")
    TPCCPolicyClassID = response.results[-1].int64_value
    
    time.sleep(5)

    StartTime = time.perf_counter()
    # Import collections
    for collection in collections:
        try:
            oa_id = ImportDoccument(collection, TPCCPolicyClassID)
            ObjectAttributeIDs[collection] = oa_id
        except Exception as e:
            continue
    EndTime = time.perf_counter()
    print(f"It took {EndTime - StartTime:0.4f} seconds to import all collections and create OAs and Os")
    time.sleep(5)

    ObjectsToGrantSuperPermsOn = [
        -2,
        -3,
        -4,
        -5,
        -6,
        -7,
        ObjectAttributeIDs["CUSTOMER"],
        ObjectAttributeIDs["DISTRICT"],
        ObjectAttributeIDs["HISTORY"],
        ObjectAttributeIDs["ITEM"],
        ObjectAttributeIDs["NEW_ORDER"],
        ObjectAttributeIDs["ORDERS"],
        ObjectAttributeIDs["STOCK"],
        ObjectAttributeIDs["WAREHOUSE"]
    ]
    StartTime = time.perf_counter()
    for objectID in ObjectsToGrantSuperPermsOn:
        GrantPermsToSuper = cmd_pb2.AdminCommand(
                associate_cmd=cmd_pb2.AssociateCmd(
                    ua_id=2,
                    target_id=objectID,
                    arset=["read", "assign", "assign_to", "associate", "associate_to", "create_user", "create_user_attribute", "create_object", "create_object_attribute", "create_policy_class", "create_prohibition", "*a", "*", "*r"]
                )
        )
        response = adminStub.AdjudicateAdminCmd(
                    pdp_adjudication_pb2.AdminCmdRequest(commands=[GrantPermsToSuper]),
                    metadata=metadata
    )
    UserAttributeIDs["super"] = 2

    # Guarentee super has proper perms on everything   
    for key in ObjectIDs:
        objectID = ObjectIDs[key]
        GrantPermsToSuper = cmd_pb2.AdminCommand(
                associate_cmd=cmd_pb2.AssociateCmd(
                    ua_id=2,
                    target_id=objectID,
                    arset=["read", "assign", "assign_to", "associate", "associate_to", "create_user", "create_user_attribute", "create_object", "create_object_attribute", "create_policy_class", "create_prohibition", "*a", "*", "*r"]
                )
        )
        response = adminStub.AdjudicateAdminCmd(
                    pdp_adjudication_pb2.AdminCmdRequest(commands=[GrantPermsToSuper]),
                    metadata=metadata
    )
    EndTime = time.perf_counter()
    print(f"It took {EndTime - StartTime:0.4f} seconds to grant super user all permissions on all nodes")

    StartTime = time.perf_counter()
    CreatePublicAndPrivateFieldsOAs(TPCCPolicyClassID)
    EndTime = time.perf_counter()
    print(f"It took {EndTime - StartTime:0.4f} seconds to create Public and Private Profile Fields OAs and associate corresping fields")

    time.sleep(5)
    StartTime = time.perf_counter()
    CreateWebAppAccountAndAssociations(TPCCPolicyClassID)
    EndTime = time.perf_counter()
    print(f"It took {EndTime - StartTime:0.4f} seconds to create web app user account, UA, and associations")

    # CreateDeveloperUACommand = cmd_pb2.AdminCommand(
    #         create_user_attribute_cmd=cmd_pb2.CreateUserAttributeCmd(
    #             name="DeveloperUA",
    #             descendants=[TPCCPolicyClassID]
    #         )
    # )

    # response = adminStub.AdjudicateAdminCmd(
    #             pdp_adjudication_pb2.AdminCmdRequest(commands=[CreateDeveloperUACommand]),
    #             metadata=metadata
    # )
    # DeveloperUAID = response.results[-1].int64_value
    # UserAttributeIDs["alice.smith@company.com"] = DeveloperUAID
    # time.sleep(5)

    # CreateDeveloperUserCommand = cmd_pb2.AdminCommand(
    #         create_user_cmd=cmd_pb2.CreateUserCmd(
    #             name="alice.smith@company.com",
    #             descendants=[DeveloperUAID]
    #         )
    # )
    # response = adminStub.AdjudicateAdminCmd(
    #             pdp_adjudication_pb2.AdminCmdRequest(commands=[CreateDeveloperUserCommand]),
    #             metadata=metadata
    # )
    # DeveloperUserID = response.results[-1].int64_value
    # UserIDs["alice.smith@company.com"] = DeveloperUserID


    # # Grant permissions to Developer
    # GrantPermsToDeveloper = cmd_pb2.AdminCommand(
    #             associate_cmd=cmd_pb2.AssociateCmd(
    #                 ua_id=DeveloperUAID,
    #                 target_id=ObjectAttributeIDs['Public_Profile_Fields'],
    #                 arset=["read"]
    #             )
    #     )
    # response = adminStub.AdjudicateAdminCmd(
    #                 pdp_adjudication_pb2.AdminCmdRequest(commands=[GrantPermsToDeveloper]),
    #                 metadata=metadata
    #     )
    # time.sleep(5)
    # # Define Prohibitions for developer
    # CreateDeveloperProhibitionsCommand = cmd_pb2.AdminCommand(
    #             create_prohibition_cmd=cmd_pb2.CreateProhibitionCmd(
    #                 name = "DeveloperProhibitions_"+ "Private_Profile_Fields",
    #                 node_id = DeveloperUAID,
    #                 arset = ["read", "write"],
    #                 intersection = False,
    #                 container_conditions=[
    #                     cmd_pb2.CreateProhibitionCmd.ContainerCondition(
    #                         container_id=ObjectAttributeIDs["Private_Profile_Fields"], 
    #                         complement=False
    #                     )
    #                 ]
    #             )
    #     )
    # response = adminStub.AdjudicateAdminCmd(
    #                 pdp_adjudication_pb2.AdminCmdRequest(commands=[CreateDeveloperProhibitionsCommand]),
    #                 metadata=metadata
    # )

    StartTime = time.perf_counter()
    CreateDeveloperUACommand = cmd_pb2.AdminCommand(
            create_user_attribute_cmd=cmd_pb2.CreateUserAttributeCmd(
                name="DeveloperUA",
                descendants=[TPCCPolicyClassID]
            )
    )

    response = adminStub.AdjudicateAdminCmd(
                pdp_adjudication_pb2.AdminCmdRequest(commands=[CreateDeveloperUACommand]),
                metadata=metadata
    )
    EndTime = time.perf_counter()
    print(f"It took {EndTime - StartTime:0.4f} seconds to create Developer UA")

    DeveloperUAID = response.results[-1].int64_value
    UserAttributeIDs["alice.smith@company.com"] = DeveloperUAID
    time.sleep(5)

    # Create Developer User
    StartTime = time.perf_counter()
    CreateDeveloperUserCommand = cmd_pb2.AdminCommand(
            create_user_cmd=cmd_pb2.CreateUserCmd(
                name="alice.smith@company.com",
                descendants=[DeveloperUAID]
            )
    )
    response = adminStub.AdjudicateAdminCmd(
                pdp_adjudication_pb2.AdminCmdRequest(commands=[CreateDeveloperUserCommand]),
                metadata=metadata
    )
    EndTime = time.perf_counter()
    print(f"It took {EndTime - StartTime:0.4f} seconds to create Developer user")

    DeveloperUserID = response.results[-1].int64_value
    UserAttributeIDs["alice.smith@company.com"] = DeveloperUAID

    # Grant permissions to Developer
    DeveloperProhibitions = [
    "CUSTOMER_C_ID", "CUSTOMER_C_D_ID", "CUSTOMER_C_W_ID", "CUSTOMER_C_STREET_1", "CUSTOMER_C_STREET_2",
    "CUSTOMER_C_CITY", "CUSTOMER_C_STATE", "CUSTOMER_C_ZIP", "CUSTOMER_C_PHONE", "CUSTOMER_C_SINCE",
    "CUSTOMER_C_CREDIT", "CUSTOMER_C_CREDIT_LIM", "CUSTOMER_C_DISCOUNT", "CUSTOMER_C_BALANCE",
    "CUSTOMER_C_YTD_PAYMENT", "CUSTOMER_C_PAYMENT_CNT", "CUSTOMER_C_DELIVERY_CNT", "CUSTOMER_C_DATA", # END CUSTOMER
    "DISTRICT_D_ID", "DISTRICT_D_W_ID", "DISTRICT_D_STREET_1", "DISTRICT_D_STREET_2",
    "DISTRICT_D_CITY", "DISTRICT_D_STATE", "DISTRICT_D_ZIP", "DISTRICT_D_TAX", "DISTRICT_D_YTD",
    "DISTRICT_D_NEXT_O_ID", # END DISTRICT
    "HISTORY_H_C_ID", "HISTORY_H_C_D_ID", "HISTORY_H_C_W_ID", "HISTORY_H_D_ID", "HISTORY_H_W_ID", 
    "HISTORY_H_AMOUNT", "HISTORY_H_DATA", # END HISTORY
    "ITEM_I_ID", "ITEM_I_IM_ID", "ITEM_I_DATA", "ITEM_I_W_ID", # END ITEM
    "NEW_ORDER_NO_O_ID", "NEW_ORDER_NO_D_ID", "NEW_ORDER_NO_W_ID", # END NEW_ORDER
    "ORDERS_O_ID", "ORDERS_O_C_ID", "ORDERS_O_D_ID", "ORDERS_O_W_ID", "ORDERS_O_CARRIER_ID",
    "ORDERS_O_OL_CNT", "ORDERS_O_ALL_LOCAL", "ORDERS_ORDER_LINE", # END ORDERS
    "STOCK_S_I_ID", "STOCK_S_W_ID", "STOCK_S_DIST_01", "STOCK_S_DIST_02", "STOCK_S_DIST_03",
    "STOCK_S_DIST_04", "STOCK_S_DIST_05", "STOCK_S_DIST_06", "STOCK_S_DIST_07", "STOCK_S_DIST_08", "STOCK_S_DIST_09",
    "STOCK_S_DIST_10", "STOCK_S_YTD", "STOCK_S_DATA", # END STOCK
    "WAREHOUSE_W_ID", "WAREHOUSE_W_TAX", "WAREHOUSE_W_YTD" # END WAREHOUSE
    ]


    ColumnsToGrantAccessTo = [
        "CUSTOMER_C_FIRST", "CUSTOMER_C_MIDDLE", "CUSTOMER_C_LAST", # END CUSTOMER
        "DISTRICT_D_NAME", # END DISTRICT
        "HISTORY_H_DATE", # END HISTORY
        "ITEM_I_NAME", "ITEM_I_PRICE", # END ITEM
        "ORDERS_O_ENTRY_D", "ORDERS_O_OL_CNT", # END ORDERS
        "STOCK_S_QUANTITY", "STOCK_S_ORDER_CNT", "STOCK_S_REMOTE_CNT", # END STOCK
        "WAREHOUSE_W_NAME", "WAREHOUSE_W_STREET_1", "WAREHOUSE_W_STREET_2", 
        "WAREHOUSE_W_CITY", "WAREHOUSE_W_STATE", "WAREHOUSE_W_ZIP" # END WAREHOUSE
    ]

    StartTime = time.perf_counter()
    for column in ColumnsToGrantAccessTo:
        GrantPermsToDeveloper = cmd_pb2.AdminCommand(
                associate_cmd=cmd_pb2.AssociateCmd(
                    ua_id=DeveloperUAID,
                    target_id=ObjectIDs[column],
                    arset=["read"]
                )
        )
        response = adminStub.AdjudicateAdminCmd(
                    pdp_adjudication_pb2.AdminCmdRequest(commands=[GrantPermsToDeveloper]),
                    metadata=metadata
        )

    # Define Prohibitions for developer
    for value in DeveloperProhibitions:
        CreateDeveloperProhibitionsCommand = cmd_pb2.AdminCommand(
                create_prohibition_cmd=cmd_pb2.CreateProhibitionCmd(
                    name = "DeveloperProhibitions_"+ str(value),
                    node_id = DeveloperUAID,
                    arset = ["read", "write"],
                    intersection = False,
                    container_conditions=[
                        cmd_pb2.CreateProhibitionCmd.ContainerCondition(
                            container_id=ObjectIDs[value], 
                            complement=False
                        )
                    ]
                )
        )
        response = adminStub.AdjudicateAdminCmd(
                        pdp_adjudication_pb2.AdminCmdRequest(commands=[CreateDeveloperProhibitionsCommand]),
                        metadata=metadata
        )
    EndTime = time.perf_counter()
    print(f"It took {EndTime - StartTime:0.4f} seconds to grant Developer user permissions and prohibitions")

    StartTime = time.perf_counter()
    # Create HR Employee UA
    CreateHREmployeeCommand = cmd_pb2.AdminCommand(
            create_user_attribute_cmd=cmd_pb2.CreateUserAttributeCmd(
                name="HREmployeeUA",
                descendants=[TPCCPolicyClassID]
            )
    )

    response = adminStub.AdjudicateAdminCmd(
                pdp_adjudication_pb2.AdminCmdRequest(commands=[CreateHREmployeeCommand]),
                metadata=metadata
    )
    EndTime = time.perf_counter()
    print(f"It took {EndTime - StartTime:0.4f} seconds to create HR Employee UA")

    HREmployeeUAID = response.results[-1].int64_value
    time.sleep(5)

    
    # Create HR Employee User
    StartTime = time.perf_counter()
    CreateHREmployeeUserCommand = cmd_pb2.AdminCommand(
            create_user_cmd=cmd_pb2.CreateUserCmd(
                name="Henry.Jones@company.com",
                descendants=[HREmployeeUAID]
            )
    )
    response = adminStub.AdjudicateAdminCmd(
                pdp_adjudication_pb2.AdminCmdRequest(commands=[CreateHREmployeeUserCommand]),
                metadata=metadata
    )
    EndTime = time.perf_counter()
    print(f"It took {EndTime - StartTime:0.4f} seconds to create HR Employee user")

    HREmployeeUserID = response.results[-1].int64_value
    UserAttributeIDs["Henry.Jones@company.com"] = HREmployeeUAID
    UserIDs["Henry.Jones@company.com"] = HREmployeeUserID

    # Grant permissions to HR Employee
    HREmployeeProhibitions = [
    "CUSTOMER_C_ID", "CUSTOMER_C_D_ID", "CUSTOMER_C_W_ID", # END CUSTOMER
    "DISTRICT_D_ID", "DISTRICT_D_W_ID", "DISTRICT_D_NEXT_O_ID", # END DISTRICT
    "HISTORY_H_C_ID", "HISTORY_H_C_D_ID", "HISTORY_H_C_W_ID", "HISTORY_H_D_ID", "HISTORY_H_W_ID",# END HISTORY
    "ITEM_I_ID", "ITEM_I_IM_ID", "ITEM_I_W_ID", # END ITEM
    "NEW_ORDER_NO_O_ID", "NEW_ORDER_NO_D_ID", "NEW_ORDER_NO_W_ID", # END NEW_ORDER
    "ORDERS_O_ID", "ORDERS_O_C_ID", "ORDERS_O_D_ID", "ORDERS_O_W_ID", "ORDERS_O_CARRIER_ID", # END ORDERS
    "STOCK_S_I_ID", "STOCK_S_W_ID", # END STOCK
    "WAREHOUSE_W_ID" # END WAREHOUSE
    ]


    ColumnsToGrantHRAccessTo = [
        "CUSTOMER_C_FIRST", "CUSTOMER_C_MIDDLE", "CUSTOMER_C_LAST",
        "CUSTOMER_C_STREET_1", "CUSTOMER_C_STREET_2", "CUSTOMER_C_CITY", "CUSTOMER_C_STATE", 
        "CUSTOMER_C_ZIP", "CUSTOMER_C_PHONE", "CUSTOMER_C_SINCE", "CUSTOMER_C_CREDIT", 
        "CUSTOMER_C_CREDIT_LIM", "CUSTOMER_C_DISCOUNT", "CUSTOMER_C_BALANCE", "CUSTOMER_C_YTD_PAYMENT",
        "CUSTOMER_C_PAYMENT_CNT", "CUSTOMER_C_DELIVERY_CNT", "CUSTOMER_C_DATA", # END CUSTOMER
        "DISTRICT_D_NAME", "DISTRICT_D_STREET_1", "DISTRICT_D_STREET_2", "DISTRICT_D_CITY",
        "DISTRICT_D_STATE", "DISTRICT_D_ZIP", "DISTRICT_D_TAX", "DISTRICT_D_YTD", # END DISTRICT
        "HISTORY_H_DATE", "HISTORY_H_AMOUNT", "HISTORY_H_DATA", # END HISTORY
        "ITEM_I_NAME", "ITEM_I_PRICE", "ITEM_I_DATA", # END ITEM
        "ORDERS_O_ENTRY_D", "ORDERS_O_OL_CNT", "ORDERS_O_OL_CNT", "ORDERS_O_ALL_LOCAL", "ORDERS_ORDER_LINE", # END ORDERS
        "STOCK_S_QUANTITY", "STOCK_S_ORDER_CNT", "STOCK_S_REMOTE_CNT", "STOCK_S_DIST_01", "STOCK_S_DIST_02", "STOCK_S_DIST_03",
        "STOCK_S_DIST_04", "STOCK_S_DIST_05", "STOCK_S_DIST_06", "STOCK_S_DIST_07", "STOCK_S_DIST_08", "STOCK_S_DIST_09",
        "STOCK_S_DIST_10", "STOCK_S_YTD", "STOCK_S_DATA", # END STOCK
        "WAREHOUSE_W_NAME", "WAREHOUSE_W_STREET_1", "WAREHOUSE_W_STREET_2", 
        "WAREHOUSE_W_CITY", "WAREHOUSE_W_STATE", "WAREHOUSE_W_ZIP", "WAREHOUSE_W_TAX", "WAREHOUSE_W_YTD" # END WAREHOUSE
    ]

    StartTime = time.perf_counter()
    for column in ColumnsToGrantHRAccessTo:
        GrantPermsToHREmployee = cmd_pb2.AdminCommand(
                associate_cmd=cmd_pb2.AssociateCmd(
                    ua_id=HREmployeeUAID,
                    target_id=ObjectIDs[column],
                    arset=["read", "write"]
                )
        )
        response = adminStub.AdjudicateAdminCmd(
                    pdp_adjudication_pb2.AdminCmdRequest(commands=[GrantPermsToHREmployee]),
                    metadata=metadata
        )
    
    for value in HREmployeeProhibitions:
        CreateHRProhibitionsCommand = cmd_pb2.AdminCommand(
                create_prohibition_cmd=cmd_pb2.CreateProhibitionCmd(
                    name = "HREmployeeProhibitions_"+ str(value),
                    node_id = HREmployeeUAID,
                    arset = ["read", "write"],
                    intersection = False,
                    container_conditions=[
                        cmd_pb2.CreateProhibitionCmd.ContainerCondition(
                            container_id=ObjectIDs[value], 
                            complement=False
                        )
                    ]
                )
        )
        response = adminStub.AdjudicateAdminCmd(
                        pdp_adjudication_pb2.AdminCmdRequest(commands=[CreateHRProhibitionsCommand]),
                        metadata=metadata
        )
    EndTime = time.perf_counter()
    print(f"It took {EndTime - StartTime:0.4f} seconds to grant HR Employee user permissions and prohibitions")

    print("Graph Initalization completed!")



def ImportDoccument(CollectionName, TPCCPolicyClassID):
    channel = grpc.insecure_channel('localhost:50052')
    metadata = grpc.aio.Metadata(('x-pm-user', 'super'), ('x-pm-attrs', '2'))
    admin_stub = pdp_adjudication_pb2_grpc.AdminAdjudicationServiceStub(channel)

    cnxnString = "mongodb://sudo:mysecretpassword22%40@localhost:27017/?authSource=admin"
    client = MongoClient(cnxnString)
    TPCCDB = client.tpcc
    Collection = TPCCDB[CollectionName]

    commandFunc = cmd_pb2.AdminCommand(
            create_object_attribute_cmd=cmd_pb2.CreateObjectAttributeCmd(
                name=CollectionName + "OA",
                descendants=[TPCCPolicyClassID]
            )
        )
    response = admin_stub.AdjudicateAdminCmd(
                pdp_adjudication_pb2.AdminCmdRequest(commands=[commandFunc]),
                metadata=metadata
            )
    
    if response.results and hasattr(response.results[-1], 'int64_value'):
            ObjectAttributeID = response.results[-1].int64_value
    
    
    # Wait for OA propagation
    time.sleep(5)
    
    # Import documents
    columns = GetFieldNames(Collection)

    for value in columns:
        obj_cmd = cmd_pb2.AdminCommand(
            create_object_cmd=cmd_pb2.CreateObjectCmd(
                name=f"{CollectionName}_{value}",
                descendants=[ObjectAttributeID]
            )
        )
        obj_response = admin_stub.AdjudicateAdminCmd(
                pdp_adjudication_pb2.AdminCmdRequest(commands=[obj_cmd]),
                metadata=metadata
        )
        ObjectIDs[f"{CollectionName}_{value}"] = obj_response.results[-1].int64_value

    return ObjectAttributeID

def CreatePublicAndPrivateFieldsOAs(TPCCPolicyClassID):
    channel = grpc.insecure_channel('localhost:50052')
    metadata = grpc.aio.Metadata(('x-pm-user', 'super'), ('x-pm-attrs', '2'))
    adminStub = pdp_adjudication_pb2_grpc.AdminAdjudicationServiceStub(channel)
    query_stub = pdp_query_pb2_grpc.PolicyQueryServiceStub(channel)

    # Create Public Profile Fields OA
    CreatePublicProfileFieldsCMD = cmd_pb2.AdminCommand(
            create_object_attribute_cmd=cmd_pb2.CreateObjectAttributeCmd(
                name="Public_Profile_Fields",
                descendants=[TPCCPolicyClassID]
            )
        )
    response = adminStub.AdjudicateAdminCmd(
                pdp_adjudication_pb2.AdminCmdRequest(commands=[CreatePublicProfileFieldsCMD]),
                metadata=metadata
            )
    
    if response.results and hasattr(response.results[-1], 'int64_value'):
            Public_Profile_FieldsOA = response.results[-1].int64_value
            ObjectAttributeIDs["Public_Profile_Fields"] = Public_Profile_FieldsOA
            
    # Wait for PUBLIC OA propagation
    time.sleep(5)


    # Create Private Profile Fields OA
    CreatePrivateProfileFieldsCMD = cmd_pb2.AdminCommand(
            create_object_attribute_cmd=cmd_pb2.CreateObjectAttributeCmd(
                name="Private_Profile_Fields",
                descendants=[TPCCPolicyClassID]
            )
        )
    response = adminStub.AdjudicateAdminCmd(
                pdp_adjudication_pb2.AdminCmdRequest(commands=[CreatePrivateProfileFieldsCMD]),
                metadata=metadata
            )
    
    if response.results and hasattr(response.results[-1], 'int64_value'):
            Private_Profile_FieldsOA = response.results[-1].int64_value
            ObjectAttributeIDs["Private_Profile_Fields"] = Private_Profile_FieldsOA
            
    # Wait for PRIVATE OA propagation
    time.sleep(5)

    # Define Public and Private fields then create associations between OAs and fields
    PrivateFields = [
    "CUSTOMER_C_ID", "CUSTOMER_C_D_ID", "CUSTOMER_C_W_ID", "CUSTOMER_C_STREET_1", "CUSTOMER_C_STREET_2",
    "CUSTOMER_C_CITY", "CUSTOMER_C_STATE", "CUSTOMER_C_ZIP", "CUSTOMER_C_PHONE", "CUSTOMER_C_SINCE",
    "CUSTOMER_C_CREDIT", "CUSTOMER_C_CREDIT_LIM", "CUSTOMER_C_DISCOUNT", "CUSTOMER_C_BALANCE",
    "CUSTOMER_C_YTD_PAYMENT", "CUSTOMER_C_PAYMENT_CNT", "CUSTOMER_C_DELIVERY_CNT", "CUSTOMER_C_DATA", # END CUSTOMER
    "DISTRICT_D_ID", "DISTRICT_D_W_ID", "DISTRICT_D_STREET_1", "DISTRICT_D_STREET_2",
    "DISTRICT_D_CITY", "DISTRICT_D_STATE", "DISTRICT_D_ZIP", "DISTRICT_D_TAX", "DISTRICT_D_YTD",
    "DISTRICT_D_NEXT_O_ID", # END DISTRICT
    "HISTORY_H_C_ID", "HISTORY_H_C_D_ID", "HISTORY_H_C_W_ID", "HISTORY_H_D_ID", "HISTORY_H_W_ID", 
    "HISTORY_H_AMOUNT", "HISTORY_H_DATA", # END HISTORY
    "ITEM_I_ID", "ITEM_I_IM_ID", "ITEM_I_DATA", "ITEM_I_W_ID", # END ITEM
    "NEW_ORDER_NO_O_ID", "NEW_ORDER_NO_D_ID", "NEW_ORDER_NO_W_ID", # END NEW_ORDER
    "ORDERS_O_ID", "ORDERS_O_C_ID", "ORDERS_O_D_ID", "ORDERS_O_W_ID", "ORDERS_O_CARRIER_ID",
    "ORDERS_O_OL_CNT", "ORDERS_O_ALL_LOCAL", "ORDERS_ORDER_LINE", # END ORDERS
    "STOCK_S_I_ID", "STOCK_S_W_ID", "STOCK_S_DIST_01", "STOCK_S_DIST_02", "STOCK_S_DIST_03",
    "STOCK_S_DIST_04", "STOCK_S_DIST_05", "STOCK_S_DIST_06", "STOCK_S_DIST_07", "STOCK_S_DIST_08", "STOCK_S_DIST_09",
    "STOCK_S_DIST_10", "STOCK_S_YTD", "STOCK_S_DATA", # END STOCK
    "WAREHOUSE_W_ID", "WAREHOUSE_W_TAX", "WAREHOUSE_W_YTD" # END WAREHOUSE
    ]


    PublicFields = [
        "CUSTOMER_C_FIRST", "CUSTOMER_C_MIDDLE", "CUSTOMER_C_LAST", # END CUSTOMER
        "DISTRICT_D_NAME", # END DISTRICT
        "HISTORY_H_DATE", # END HISTORY
        "ITEM_I_NAME", "ITEM_I_PRICE", # END ITEM
        "ORDERS_O_ENTRY_D", "ORDERS_O_OL_CNT", # END ORDERS
        "STOCK_S_QUANTITY", "STOCK_S_ORDER_CNT", "STOCK_S_REMOTE_CNT", # END STOCK
        "WAREHOUSE_W_NAME", "WAREHOUSE_W_STREET_1", "WAREHOUSE_W_STREET_2", 
        "WAREHOUSE_W_CITY", "WAREHOUSE_W_STATE", "WAREHOUSE_W_ZIP" # END WAREHOUSE
    ]

    # make public objects descendents of Public_Profile_Fields OA
    for key in PublicFields:
        objectID = ObjectIDs[key]
        query = pdp_query_pb2.GetAdjacentAssignmentsQuery(node_id=objectID)
        current_parents = query_stub.GetAdjacentDescendants(query, metadata=metadata, timeout=5)

        all_parent_ids = [parent.id for parent in current_parents.nodes]
        all_parent_ids.append(Public_Profile_FieldsOA)
        #Remove duplicates
        all_parent_ids = list(set(all_parent_ids))

        assignCMD = cmd_pb2.AdminCommand(
                assign_cmd=cmd_pb2.AssignCmd(
                    ascendant_id=objectID,
                    descendant_ids=all_parent_ids
                )
            )
        response = adminStub.AdjudicateAdminCmd(
            pdp_adjudication_pb2.AdminCmdRequest(commands=[assignCMD]),
            metadata=metadata
        )

    # make private objects descendents of Private_Profile_Fields OA
    for key in PrivateFields:
        objectID = ObjectIDs[key]
        query = pdp_query_pb2.GetAdjacentAssignmentsQuery(node_id=objectID)
        current_parents = query_stub.GetAdjacentDescendants(query, metadata=metadata, timeout=5)

        all_parent_ids = [parent.id for parent in current_parents.nodes]
        all_parent_ids.append(Private_Profile_FieldsOA)
        #Remove duplicates
        all_parent_ids = list(set(all_parent_ids))

        assignCMD = cmd_pb2.AdminCommand(
                assign_cmd=cmd_pb2.AssignCmd(
                    ascendant_id=objectID,
                    descendant_ids=all_parent_ids
                )
            )
        response = adminStub.AdjudicateAdminCmd(
            pdp_adjudication_pb2.AdminCmdRequest(commands=[assignCMD]),
            metadata=metadata
        )

def CreateWebAppAccountAndAssociations(TPCCPolicyClassID):
    channel = grpc.insecure_channel('localhost:50052')
    metadata = grpc.aio.Metadata(('x-pm-user', 'super'), ('x-pm-attrs', '2'))
    adminStub = pdp_adjudication_pb2_grpc.AdminAdjudicationServiceStub(channel)
    
    # Create WebApp Service Account UA
    CreateWebServiceAccountUACommand = cmd_pb2.AdminCommand(
            create_user_attribute_cmd=cmd_pb2.CreateUserAttributeCmd(
                name="WebApp_Service_Account",
                descendants=[TPCCPolicyClassID]
            )
    )

    response = adminStub.AdjudicateAdminCmd(
                pdp_adjudication_pb2.AdminCmdRequest(commands=[CreateWebServiceAccountUACommand]),
                metadata=metadata
    )
    WebApp_Service_Account_ID = response.results[-1].int64_value
    UserAttributeIDs["WebApp_Service_Account"] = WebApp_Service_Account_ID
    time.sleep(5)

    #create WebApp Service Account User
    CreateWebAppServiceUserCommand = cmd_pb2.AdminCommand(
            create_user_cmd=cmd_pb2.CreateUserCmd(
                name="WebApp_Service_Account_User",
                descendants=[WebApp_Service_Account_ID]
            )
    )
    response = adminStub.AdjudicateAdminCmd(
                pdp_adjudication_pb2.AdminCmdRequest(commands=[CreateWebAppServiceUserCommand]),
                metadata=metadata
    )
    WebApp_Service_Account_UserID = response.results[-1].int64_value
    UserIDs["WebApp_Service_Account_User"] = WebApp_Service_Account_UserID

   
    # Web_Service_Account --> Read --> Public_Profile_Fields
    CreateAssociationCMD = cmd_pb2.AdminCommand(
        associate_cmd=cmd_pb2.AssociateCmd(
            ua_id=WebApp_Service_Account_ID,
            target_id=ObjectAttributeIDs["Public_Profile_Fields"],
            arset=["read"]
        )
    )
    response = adminStub.AdjudicateAdminCmd(
                pdp_adjudication_pb2.AdminCmdRequest(commands=[CreateAssociationCMD]),
                metadata=metadata
    )


############################### ======= Flask App functions ======= #######################################

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def verify_password(password, hashed):
    return hash_password(password) == hashed

def login_required(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        if "username" not in session:
            return redirect(url_for('login'))
        return func(*args, **kwargs)
    return wrapper


def get_all_employee_records():
    cnxnString = build_connection_string()
    client = MongoClient(cnxnString)
    OrganizationDB = client.Organization
    EmployeesCollection = OrganizationDB.Employees
    employees = list(EmployeesCollection.find({},{}))
    return employees


def get_all_professor_records():
    cnxnString = build_connection_string()
    client = MongoClient(cnxnString)
    schoolDB = client.school
    professorsCollection = schoolDB.professors
    professors = list(professorsCollection.find({},{"name":1, "subject":1, "email":1, "ssn":1}))
    return professors

def build_connection_string():
    parsedUsername = urllib.parse.quote_plus(session['username'])
    parsedPassword = urllib.parse.quote_plus(session['password'])
    return "mongodb://%s:%s@localhost:27017/?authSource=admin" % (parsedUsername, parsedPassword)


############################################## ======= Benchmarking ========= ###################################################

def BenchmarkingNGACPerformance():
    parsedUsername = urllib.parse.quote_plus("alice.smith@company.com")
    parsedPassword = urllib.parse.quote_plus('mysecretpassword22@')
    cnxnString =  "mongodb://%s:%s@localhost:27017/?authSource=admin" % (parsedUsername, parsedPassword)

    client = MongoClient(cnxnString)
    TPCCDB = client.tpcc
    ItemsCollection = TPCCDB.ITEM
    CustomersCollection = TPCCDB.CUSTOMER

    CustomersList = [
        ObjectIDs["CUSTOMER_C_ID"], ObjectIDs["CUSTOMER_C_D_ID"], ObjectIDs["CUSTOMER_C_W_ID"],
        ObjectIDs["CUSTOMER_C_FIRST"], ObjectIDs["CUSTOMER_C_MIDDLE"], ObjectIDs["CUSTOMER_C_LAST"],
        ObjectIDs["CUSTOMER_C_STREET_1"], ObjectIDs["CUSTOMER_C_STREET_2"], ObjectIDs["CUSTOMER_C_CITY"],
        ObjectIDs["CUSTOMER_C_STATE"], ObjectIDs["CUSTOMER_C_ZIP"], ObjectIDs["CUSTOMER_C_PHONE"],
        ObjectIDs["CUSTOMER_C_SINCE"], ObjectIDs["CUSTOMER_C_CREDIT"], ObjectIDs["CUSTOMER_C_CREDIT_LIM"],
        ObjectIDs["CUSTOMER_C_DISCOUNT"], ObjectIDs["CUSTOMER_C_BALANCE"], ObjectIDs["CUSTOMER_C_YTD_PAYMENT"],
        ObjectIDs["CUSTOMER_C_PAYMENT_CNT"], ObjectIDs["CUSTOMER_C_DELIVERY_CNT"], ObjectIDs["CUSTOMER_C_DATA"]
    ]

    ItemsList = [
        ObjectIDs["ITEM_I_ID"], ObjectIDs["ITEM_I_IM_ID"], ObjectIDs["ITEM_I_NAME"],
        ObjectIDs["ITEM_I_PRICE"], ObjectIDs["ITEM_I_DATA"], ObjectIDs["ITEM_I_W_ID"]
    ]

    projection = {}  

    # ==========================-    Alice Smith testing    -===============================
    print("=========Beginning benchmarking tests for Alice Smith Find Query On Customers Collection=======")
    StartTime = time.perf_counter()
    ListOfAllowed = CheckUserProhibition("alice.smith@company.com", CustomersList, "read", UserAttributeIDs["alice.smith@company.com"])

    for item in ListOfAllowed:
        key = GetKeyByValue(item)
        key = key.removeprefix("CUSTOMER_")
        projection.update({key: 1})

    results = list(CustomersCollection.find(
                {"C_FIRST":{"$regex": "a", "$options": "i"}},
                projection
            ))
    EndTime = time.perf_counter()
    #print(f"Query was rewritten for read permissions on the following fields of the CUSTOMER Collection: {projection}")
    print(f"NGAC Alice Smith Customer Find Query Execution Time: {EndTime - StartTime:0.4f}")
    
    # ===============================-    End Alice Smith testing    -===============================


    # ==========================-    Super user testing    -===============================

    parsedUsername = urllib.parse.quote_plus("super")
    parsedPassword = urllib.parse.quote_plus('mysecretpassword22@')
    cnxnString =  "mongodb://%s:%s@localhost:27017/?authSource=admin" % (parsedUsername, parsedPassword)
    client = MongoClient(cnxnString)

    print("=========Beginning benchmarking tests for Super User Find Query On CUSTOMER Collection=======")
    StartTime = time.perf_counter()
    ListOfAllowed = CheckUserProhibition("super", CustomersList, "read", UserAttributeIDs["super"])

    projection = {}
    for item in ListOfAllowed:
        key = GetKeyByValue(item)
        key = key.removeprefix("CUSTOMER_")
        projection.update({key: 1})

    if len(ListOfAllowed) == len(CustomersList):
        results = list(CustomersCollection.find(
            {"C_FIRST":{"$regex": "a", "$options": "i"}},
            {"C_ID":1, "C_D_ID":1, "C_W_ID":1, "C_FIRST":1, "C_MIDDLE":1, "C_LAST":1,
            "C_STREET_1":1, "C_STREET_2":1, "C_CITY":1, "C_STATE":1, "C_ZIP":1,
            "C_PHONE":1, "C_SINCE":1, "C_CREDIT":1, "C_CREDIT_LIM":1,
            "C_DISCOUNT":1, "C_BALANCE":1, "C_YTD_PAYMENT":1,
            "C_PAYMENT_CNT":1, "C_DELIVERY_CNT":1, "C_DATA":1
            }
        ))
        EndTime = time.perf_counter()
        print(f"NGAC super user CUSTOMER find query execution time: {EndTime - StartTime:0.4f}")


    print("=========Beginning benchmarking tests for Super User Update Query On Items Collection=======")
    StartTime = time.perf_counter()
    ListOfAllowed = CheckUserPermissions("super", "write", UserAttributeIDs["super"], ObjectAttributeIDs["ITEM"])

    projection = {}
    for item in ListOfAllowed:
        key = GetKeyByValue(item)
        key = key.removeprefix("CUSTOMER_")
        projection.update({key: 1})

    if ObjectIDs["ITEM_I_PRICE"] in ListOfAllowed:
        ItemsCollection.update_one(
                {"I_ID": 1}, {"$set": {"I_PRICE": 25.99}} #original is 25.99
        )
        EndTime = time.perf_counter()
        print(f"NGAC super user ITEM update query execution time: {EndTime - StartTime:0.4f}")
    # ===============================-    End Super user testing    -===============================

    # ==========================-    HR Employee testing    -===============================
    parsedUsername = urllib.parse.quote_plus("Henry.Jones@company.com")
    parsedPassword = urllib.parse.quote_plus('mysecretpassword22@')
    cnxnString =  "mongodb://%s:%s@localhost:27017/?authSource=admin" % (parsedUsername, parsedPassword)
    client = MongoClient(cnxnString)

    print("=========Beginning benchmarking tests for HR Employee Find Query On CUSTOMER Collection=======")
    StartTime = time.perf_counter()
    ListOfAllowed = CheckUserProhibition("Henry.Jones@company.com", CustomersList, "read", UserAttributeIDs["Henry.Jones@company.com"])

    projection = {}
    for item in ListOfAllowed:
        key = GetKeyByValue(item)
        key = key.removeprefix("CUSTOMER_")
        projection.update({key: 1})

    results = list(CustomersCollection.find(
                {"C_FIRST":{"$regex": "a", "$options": "i"}},
                projection
            ))
    EndTime = time.perf_counter()
    #print(f"It was determined that HR Employee has read permissions on the following fields of the CUSTOMER collection: {projection}")
    print(f"NGAC HR User CUSTOMER find query executution time: {EndTime - StartTime:0.4f}")


    print("=========Beginning benchmarking tests for HR Employee Update Query On ITEM Collection=======")
    StartTime = time.perf_counter()
    ListOfAllowed = CheckUserProhibition("Henry.Jones@company.com", ItemsList, "read", UserAttributeIDs["Henry.Jones@company.com"])
    #print(f"HR Employee Took: {EndTime - StartTime:0.4f} seconds for prohibition check on ITEM collection.")
    #print(f"Prohibition Check returned the following list of ObjectIDs: {ListOfAllowed}")

    # for update queries there is no functionality to rewrite the query, so coming up with a 
    # rewritten projection is not necessary for the original code (you either have permission or you don't)
    # However, this is here for human readability (lists of ObjectIDs are not informative)
    # As a result, this logic is not being benchmarked
    projection = {}
    for item in ListOfAllowed:
        key = GetKeyByValue(item)
        key = key.removeprefix("CUSTOMER_")
        projection.update({key: 1})
    #print(f"It was determined that HR user has write permissions on the following fields of the ITEM Collection: {projection}")
    #print("now checking to see if query should be allowed or denied...")

    if ObjectIDs["ITEM_I_PRICE"] in ListOfAllowed:
        ItemsCollection.update_one(
                {"I_ID": 1}, {"$set": {"I_PRICE": 30.99}} #original is 25.99
        )
        EndTime = time.perf_counter()
        print(f"NGAC HR user ITEM update query execution time: {EndTime - StartTime:0.4f}")
    # ===============================-    End HR Employee testing    -===============================

def BenchmarkingNoNGACPerformance():
    parsedUsername = urllib.parse.quote_plus("alice.smith@company.com")
    parsedPassword = urllib.parse.quote_plus('mysecretpassword22@')
    cnxnString =  "mongodb://%s:%s@localhost:27017/?authSource=admin" % (parsedUsername, parsedPassword)

    client = MongoClient(cnxnString)
    TPCCDB = client.tpcc
    ItemsCollection = TPCCDB.ITEM
    CustomersCollection = TPCCDB.CUSTOMER  

    # ==========================-    Alice Smith testing    -===============================
    print("=========Beginning benchmarking tests for Alice Smith Find Query On Customers Collection (NO NGAC)=======")
    StartTime = time.perf_counter()
    results = list(CustomersCollection.find(
                {"C_FIRST":{"$regex": "a", "$options": "i"}},
                {"C_ID":1, "C_D_ID":1, "C_W_ID":1, "C_FIRST":1, "C_MIDDLE":1, "C_LAST":1,
                "C_STREET_1":1, "C_STREET_2":1, "C_CITY":1, "C_STATE":1, "C_ZIP":1,
                "C_PHONE":1, "C_SINCE":1, "C_CREDIT ":1, "C_CREDIT_LIM":1,
                "C_DISCOUNT":1, "C_BALANCE":1, "C_YTD_PAYMENT":1,
                "C_PAYMENT_CNT":1, "C_DELIVERY_CNT":1, "C_DATA":1
                }
            ))
    EndTime = time.perf_counter()
    print(f"NO-NGAC Alice user find query execution time: {EndTime - StartTime:0.4f}")

    # ===============================-    End Alice Smith testing    -===============================

    print("=========Beginning benchmarking tests for Super User Find Query On CUSTOMER Collection (NO NGAC)=======")
    parsedUsername = urllib.parse.quote_plus("super") 
    parsedPassword = urllib.parse.quote_plus('mysecretpassword22@')
    cnxnString =  "mongodb://%s:%s@localhost:27017/?authSource=admin" % (parsedUsername, parsedPassword)
    client = MongoClient(cnxnString)

    StartTime = time.perf_counter()
    results = list(CustomersCollection.find( 
            {"C_FIRST":{"$regex": "a", "$options": "i"}},
            {"C_ID":1, "C_D_ID":1, "C_W_ID":1, "C_FIRST":1, "C_MIDDLE":1, "C_LAST":1,
            "C_STREET_1":1, "C_STREET_2":1, "C_CITY":1, "C_STATE":1, "C_ZIP":1,
            "C_PHONE":1, "C_SINCE":1, "C_CREDIT":1, "C_CREDIT_LIM":1,
            "C_DISCOUNT":1, "C_BALANCE":1, "C_YTD_PAYMENT":1,
            "C_PAYMENT_CNT":1, "C_DELIVERY_CNT":1, "C_DATA":1
            }
        ))
    EndTime = time.perf_counter()
    print(f"NO-NGAC Super User CUSTOMER find query exectution time: {EndTime - StartTime:0.4f}")

    print("=========Beginning benchmarking tests for Super User Update Query On Items Collection (NO NGAC)=======")
    StartTime = time.perf_counter()
    ItemsCollection.update_one(
            {"I_ID": 1}, {"$set": {"I_PRICE": 40.99}} #original is 25.99
    )
    EndTime = time.perf_counter()
    print(f"NO-NGAC Super User ITEM update query execution time: {EndTime - StartTime:0.4f}")
    # ===============================-    End Super user testing    -===============================
    
    print("=========Beginning benchmarking tests for HR Employee Find Query On CUSTOMER Collection (NO NGAC)=======")
    parsedUsername = urllib.parse.quote_plus("Henry.Jones@company.com")
    parsedPassword = urllib.parse.quote_plus('mysecretpassword22@')
    cnxnString =  "mongodb://%s:%s@localhost:27017/?authSource=admin" % (parsedUsername, parsedPassword)
    client = MongoClient(cnxnString)

    StartTime = time.perf_counter()
    results = list(CustomersCollection.find(
                {"C_FIRST":{"$regex": "a", "$options": "i"}},
                {"C_ID":1, "C_D_ID":1, "C_W_ID":1, "C_FIRST":1, "C_MIDDLE":1, "C_LAST":1,
                "C_STREET_1":1, "C_STREET_2":1, "C_CITY":1, "C_STATE":1, "C_ZIP":1,
                "C_PHONE":1, "C_SINCE":1, "C_CREDIT ":1, "C_CREDIT_LIM":1,
                "C_DISCOUNT":1, "C_BALANCE":1, "C_YTD_PAYMENT":1,
                "C_PAYMENT_CNT":1, "C_DELIVERY_CNT":1, "C_DATA":1
                }
            ))
    EndTime = time.perf_counter()
    print(f"NO-NGAC HR user CUSTOMER find query execution time: {EndTime - StartTime:0.4f}")

    print("=========Beginning benchmarking tests for HR Employee Update Query On ITEM Collection (NO NGAC)=======")
    StartTime = time.perf_counter()
    ItemsCollection.update_one(
            {"I_ID": 1}, {"$set": {"I_PRICE": 45.99}} #original is 25.99
    )
    EndTime = time.perf_counter()
    print(f"NO-NGAC HR user ITEM update query execution time: {EndTime - StartTime:0.4f}")
    # ===============================-    End HR Employee testing    -===============================
    print("All NO NGAC benchmarking tests completed!")



def main():
    InitalizeGraph()
    BenchmarkingNGACPerformance()
    BenchmarkingNoNGACPerformance()

if __name__ == '__main__':
    main()
    