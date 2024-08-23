import base64
import json
import logging
import time
import random
import string
from os import remove, chmod

import boto3
from botocore.exceptions import ClientError

log = logging.getLogger(__name__)


# snippet-start:[python.example_code.workflow.ResilientService_AutoScaler]
# snippet-start:[python.cross_service.resilient_service.AutoScaler.decl]
class AutoScaler:
    """
    Encapsulates Amazon EC2 Auto Scaling and EC2 management actions.
    """

    def __init__(
        self,
        inst_type: str,
        ami_param: str,
        autoscaling_client,
        ec2_client,
        ssm_client,
        iam_client
    ):
        """
        Initializes the AutoScaler with AWS clients and resource configuration.

        :param inst_type: The type of EC2 instance to create, such as t3.micro.
        :param ami_param: The Systems Manager parameter used to look up the AMI that is created.
        :param autoscaling_client: A Boto3 EC2 Auto Scaling client.
        :param ec2_client: A Boto3 EC2 client.
        :param ssm_client: A Boto3 Systems Manager client.
        :param iam_client: A Boto3 IAM client.
        """
        self.inst_type = inst_type
        self.ami_param = ami_param
        self.autoscaling_client = autoscaling_client
        self.ec2_client = ec2_client
        self.ssm_client = ssm_client
        self.iam_client = iam_client
        self.launch_template_name = self._generate_unique_name("template")
        self.group_name = self._generate_unique_name("group")
        self.key_pair_name = self._generate_unique_name("key-pair")

        # Variables used for success
        self.instance_policy_name = self._generate_unique_name("pol")
        self.instance_role_name = self._generate_unique_name("role")
        self.instance_profile_name = self._generate_unique_name("prof")

        # Variables used for failure
        self.bad_creds_policy_name = self._generate_unique_name("bc-pol")
        self.bad_creds_role_name = self._generate_unique_name("bc-role")
        self.bad_creds_profile_name = self._generate_unique_name("bc-prof")

    @staticmethod
    def _generate_unique_name(prefix: str, length: int = 8) -> str:
        """
        Generates a unique name with the given prefix.

        :param prefix: The prefix for the name.
        :param length: The length of the random string to append to the prefix.
        :return: A unique resource name.
        """
        random_suffix = "".join(
            random.choices(string.ascii_lowercase + string.digits, k=length)
        )
        return f"{prefix}-{random_suffix}"

    @classmethod
    def from_client(cls) -> "AutoScaler":
        """
        Creates an instance of this class using Boto3 clients.

        :return: An instance of the AutoScaler class.
        """
        as_client = boto3.client("autoscaling")
        ec2_client = boto3.client("ec2")
        ssm_client = boto3.client("ssm")
        iam_client = boto3.client("iam")
        return cls(
            "t3.micro",
            "/aws/service/ami-amazon-linux-latest/amzn2-ami-hvm-x86_64-gp2",
            as_client,
            ec2_client,
            ssm_client,
            iam_client,
        )

    # snippet-end:[python.cross_service.resilient_service.AutoScaler.decl]

    # snippet-start:[python.cross_service.resilient_service.iam.CreateInstanceProfile]
    def create_instance_profile(self, policy_file: str, aws_managed_policies=(), fail: bool = False) -> str:
        """
        Creates a policy, role, and instance profile associated with instances managed by this class.

        :param policy_file: The name of a JSON file that contains the policy definition to create and attach to the role.
        :param aws_managed_policies: Additional AWS-managed policies that are attached to the role.
        :param fail: A flag to determine whether to use failure-related variables.
        :return: The ARN of the created instance profile.
        :raises Exception: If there are issues creating or attaching the policies, role, or profile.
        """

        # Select the variable set based on the fail flag
        if fail:
            policy_name = self._generate_unique_name("bc-pol")
            role_name = self._generate_unique_name("bc-role")
            profile_name = self._generate_unique_name("bc-prof")
        else:
            policy_name = self._generate_unique_name("pol")
            role_name = self._generate_unique_name("role")
            profile_name = self._generate_unique_name("prof")

        def handle_ec2_error(err, context):
            error_code = err.response["Error"]["Code"]
            if error_code == "EntityAlreadyExists":
                log.error(f"{context} already exists.")
            elif error_code == "MalformedPolicyDocument":
                log.error(
                    f"The policy document is malformed in {context}. "
                    "Please check the JSON syntax and structure of your policy document and try again."
                )
            elif error_code == "LimitExceeded":
                log.error(
                    f"Limit exceeded for {context}. "
                    "Consider deleting unused resources or requesting a limit increase from AWS."
                )
            else:
                raise

        assume_role_doc = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": "ec2.amazonaws.com"},
                    "Action": "sts:AssumeRole",
                }
            ],
        }
        with open(policy_file) as file:
            instance_policy_doc = file.read()

        policy_arn = None
        try:
            pol_response = self.iam_client.create_policy(
                PolicyName=policy_name, PolicyDocument=instance_policy_doc
            )
            policy_arn = pol_response["Policy"]["Arn"]
            log.info("Created policy with ARN %s.", policy_arn)
        except ClientError as err:
            log.error(f"Couldn't create policy {policy_name}")
            handle_ec2_error(err, f"policy {policy_name}")

        try:
            self.iam_client.create_role(
                RoleName=role_name,
                AssumeRolePolicyDocument=json.dumps(assume_role_doc),
            )
            self.iam_client.attach_role_policy(
                RoleName=role_name, PolicyArn=policy_arn
            )
            for aws_policy in aws_managed_policies:
                self.iam_client.attach_role_policy(
                    RoleName=role_name,
                    PolicyArn=f"arn:aws:iam::aws:policy/{aws_policy}",
                )
            log.info("Created role %s and attached policies.", role_name)
        except ClientError as err:
            log.error(f"Couldn't create role {role_name}!")
            handle_ec2_error(err, f"Role {role_name}")

        try:
            profile_response = self.iam_client.create_instance_profile(
                InstanceProfileName=profile_name
            )
            waiter = self.iam_client.get_waiter("instance_profile_exists")
            waiter.wait(InstanceProfileName=profile_name)
            profile_arn = profile_response["InstanceProfile"]["Arn"]
            self.iam_client.add_role_to_instance_profile(
                InstanceProfileName=profile_name,
                RoleName=role_name,
            )
            log.info(
                "Created profile %s and added role %s.",
                profile_name,
                role_name,
            )
        except ClientError as err:
            log.error(f"Failed to create {profile_name}")
            handle_ec2_error(err, f"Instance profile {profile_name}")
        return profile_arn

    # snippet-end:[python.cross_service.resilient_service.iam.CreateInstanceProfile]

    # snippet-start:[python.cross_service.resilient_service.ec2.DescribeIamInstanceProfileAssociations]
    def get_instance_profile(self, instance_id: str) -> dict:
        """
        Gets data about the profile associated with an instance.

        :param instance_id: The ID of the instance to look up.
        :return: The profile data.
        :raises Exception: If the instance profile data could not be retrieved.
        """
        try:
            response = self.ec2_client.describe_iam_instance_profile_associations(
                Filters=[{"Name": "instance-id", "Values": [instance_id]}]
            )
        except ClientError as err:
            error_code = err.response["Error"]["Code"]
            if error_code == "InvalidInstanceID.NotFound":
                log.error(
                    f"The specified instance ID {instance_id} does not exist: {err}"
                )
                raise Exception(
                    f"Couldn't get instance profile because the instance ID {instance_id} was not found. "
                    "Please ensure that the instance ID is correct and try again."
                )
            raise
        else:
            return response["IamInstanceProfileAssociations"][0]

    # snippet-end:[python.cross_service.resilient_service.ec2.DescribeIamInstanceProfileAssociations]

    # snippet-start:[python.cross_service.resilient_service.ec2.ReplaceIamInstanceProfileAssociation]
    def replace_instance_profile(
        self,
        instance_id: str,
        new_instance_profile_name: str,
        profile_association_id: str,
    ):
        """
        Replaces the profile associated with a running instance. After the profile is
        replaced, the instance is rebooted to ensure that it uses the new profile. When
        the instance is ready, Systems Manager is used to restart the Python web server.

        :param instance_id: The ID of the instance to update.
        :param new_instance_profile_name: The name of the new profile to associate with the specified instance.
        :param profile_association_id: The ID of the existing profile association for the instance.
        :raises Exception: If the profile replacement fails.
        """
        try:
            self.ec2_client.replace_iam_instance_profile_association(
                IamInstanceProfile={"Name": new_instance_profile_name},
                AssociationId=profile_association_id,
            )
            log.info(
                "Replaced instance profile for association %s with profile %s.",
                profile_association_id,
                new_instance_profile_name,
            )

            # Reboot the instance to ensure it picks up the new profile.
            self.ec2_client.reboot_instances(InstanceIds=[instance_id])
            log.info(f"Rebooting instance {instance_id} to apply the new profile.")

            # Wait for the instance to reach a running state using the waiter.
            instance_running_waiter = self.ec2_client.get_waiter("instance_running")
            instance_running_waiter.wait(InstanceIds=[instance_id])
            log.info(f"Instance {instance_id} is running and ready.")

            # Restart the Python web server using Systems Manager
            self.ssm_client.send_command(
                InstanceIds=[instance_id],
                DocumentName="AWS-RunShellScript",
                Parameters={"commands": ["cd / && sudo python3 server.py 80"]},
            )
            log.info("Restarted the Python web server on instance %s.", instance_id)
        except ClientError as err:
            error_code = err.response["Error"]["Code"]
            if error_code == "InvalidInstanceID.NotFound":
                log.error(
                    f"The specified instance ID {instance_id} does not exist: {err}"
                )
                log.error(
                    f"Couldn't replace instance profile because the instance ID {instance_id} was not found. "
                    "Please ensure that the instance ID is correct and try again."
                )
            raise

    # snippet-end:[python.cross_service.resilient_service.ec2.ReplaceIamInstanceProfileAssociation]

    # snippet-start:[python.cross_service.resilient_service.iam.DeleteInstanceProfile]
    def delete_instance_profile(self, profile_name: str, role_name: str):
        """
        Detaches a role from an instance profile, detaches policies from the role,
        and deletes all the resources.

        :param profile_name: The name of the profile to delete.
        :param role_name: The name of the role to delete.
        :raises Exception: If the instance profile, role, or policies could not be deleted.
        """
        try:
            self.iam_client.remove_role_from_instance_profile(
                InstanceProfileName=profile_name, RoleName=role_name
            )
            self.iam_client.delete_instance_profile(InstanceProfileName=profile_name)
            log.info("Deleted instance profile %s.", profile_name)
            paginator = self.iam_client.get_paginator("list_attached_role_policies")
            for page in paginator.paginate(RoleName=role_name):
                for pol in page["AttachedPolicies"]:
                    self.iam_client.detach_role_policy(
                        RoleName=role_name, PolicyArn=pol["PolicyArn"]
                    )
                    if not pol["PolicyArn"].startswith("arn:aws:iam::aws"):
                        self.iam_client.delete_policy(PolicyArn=pol["PolicyArn"])
                    log.info("Detached and deleted policy %s.", pol["PolicyName"])
            self.iam_client.delete_role(RoleName=role_name)
            log.info("Deleted role %s.", role_name)
        except ClientError as err:
            error_code = err.response["Error"]["Code"]
            if error_code == "NoSuchEntity":
                log.info(
                    "Instance profile %s doesn't exist, nothing to do.", profile_name
                )
            elif error_code == "DeleteConflict":
                log.error(
                    f"Cannot delete profile or role because of dependency issues: {err}"
                )
                raise Exception(
                    "Couldn't delete instance profile or role because they are still attached to other resources. "
                    "Ensure that all dependencies are removed before trying to delete."
                )
            raise

    # snippet-end:[python.cross_service.resilient_service.iam.DeleteInstanceProfile]

    # snippet-start:[python.cross_service.resilient_service.ec2.CreateKeyPair]
    def create_key_pair(self, key_pair_name: str) -> dict:
        """
        Creates a new key pair.

        :param key_pair_name: The name of the key pair to create.
        :return: The newly created key pair.
        :raises Exception: If the key pair could not be created.
        """
        try:
            response = self.ec2_client.create_key_pair(KeyName=key_pair_name)
            with open(f"{key_pair_name}.pem", "w") as file:
                file.write(response["KeyMaterial"])
            chmod(f"{key_pair_name}.pem", 0o600)
            log.info("Created key pair %s.", key_pair_name)
            return response
        except ClientError as err:
            log.error("Couldn't create key pair!")
            error_code = err.response["Error"]["Code"]
            if error_code == "InvalidKeyPair.Duplicate":
                log.error(
                    f"The key pair '{key_pair_name}' already exists! "
                    "Delete key or use a different name."
                )
            raise

    # snippet-end:[python.cross_service.resilient_service.ec2.CreateKeyPair]

    # snippet-start:[python.cross_service.resilient_service.ec2.DeleteKeyPair]
    def delete_key_pair(self):
        """
        Deletes a key pair from AWS and from the local file system.

        :raises Exception: If the key pair could not be deleted.
        """
        try:
            self.ec2_client.delete_key_pair(KeyName=self.key_pair_name)
            remove(f"{self.key_pair_name}.pem")
            log.info(f"Deleted key pair '{self.key_pair_name}'.")
        except FileNotFoundError:
            log.info(
                f"Key pair file '{self.key_pair_name}' doesn't exist. Nothing to do!"
            )
        except ClientError as err:
            log.error(f"Failed to delete key pair '{self.key_pair_name}'")
            error_code = err.response["Error"]["Code"]
            if error_code == "InvalidKeyPair.NotFound":
                log.error(f"Key pair {self.key_pair_name} does not exist!")
            elif error_code == "UnauthorizedOperation":
                log.error(
                    "You do not have the necessary permissions to delete a key pair. "
                    "Check your IAM policies and ensure you have the necessary permissions."
                )
            raise

    # snippet-end:[python.cross_service.resilient_service.ec2.DeleteKeyPair]

    # snippet-start:[python.cross_service.resilient_service.ec2.CreateLaunchTemplate]
    def create_template(
        self, server_startup_script_file: str, instance_policy_file: str
    ) -> dict:
        """
        Creates an Amazon EC2 launch template to use with Amazon EC2 Auto Scaling. The
        launch template specifies a Bash script in its user data field that runs after
        the instance is started. This script installs Python packages and starts a
        Python web server on the instance.

        :param server_startup_script_file: The path to a Bash script file that is run when an instance starts.
        :param instance_policy_file: The path to a file that defines a permissions policy to create and attach to the instance profile.
        :return: Information about the newly created template.
        :raises Exception: If the launch template could not be created.
        """
        template = {}
        try:
            self.create_key_pair(self.key_pair_name)
            self.create_instance_profile(
                instance_policy_file,
                aws_managed_policies=[],
            )
            with open(server_startup_script_file) as file:
                start_server_script = file.read()
            ami_latest = self.ssm_client.get_parameter(Name=self.ami_param)
            ami_id = ami_latest["Parameter"]["Value"]
            lt_response = self.ec2_client.create_launch_template(
                LaunchTemplateName=self.launch_template_name,
                LaunchTemplateData={
                    "InstanceType": self.inst_type,
                    "ImageId": ami_id,
                    "IamInstanceProfile": {"Name": self.instance_profile_name},
                    "UserData": base64.b64encode(
                        start_server_script.encode(encoding="utf-8")
                    ).decode(encoding="utf-8"),
                    "KeyName": self.key_pair_name,
                },
            )
            template = lt_response["LaunchTemplate"]
            log.info(
                "Created launch template %s for AMI %s on %s.",
                self.launch_template_name,
                ami_id,
                self.inst_type,
            )
        except ClientError as err:
            log.error(f"Failed to create launch template '{self.launch_template_name}'!")
            error_code = err.response["Error"]["Code"]
            if error_code == "InvalidLaunchTemplateName.AlreadyExistsException":
                log.info(
                    "Launch template %s already exists. Nothing to do!",
                    self.launch_template_name,
                )
            elif error_code == "InvalidParameterCombination":
                log.error(
                    "Couldn't create the launch template because of an invalid parameter combination. "
                    "Check the parameters being used in the launch template and try again."
                )
            raise
        return template

    # snippet-end:[python.cross_service.resilient_service.ec2.CreateLaunchTemplate]

    # snippet-start:[python.cross_service.resilient_service.ec2.DeleteLaunchTemplate]
    def delete_template(self):
        """
        Deletes a launch template.

        :raises Exception: If the launch template could not be deleted.
        """
        try:
            self.ec2_client.delete_launch_template(
                LaunchTemplateName=self.launch_template_name
            )
            self.delete_instance_profile(
                self.instance_profile_name, self.instance_role_name
            )
            log.info(f"Launch template {self.launch_template_name} deleted.")
        except ClientError as err:
            log.error(f"Failed to delete launch template '{self.launch_template_name}'.")
            error_code = err.response["Error"]["Code"]
            if error_code == "InvalidLaunchTemplateName.NotFoundException":
                log.info(
                    f"Launch template {self.launch_template_name} does not exist, nothing to do."
                )
            raise

    # snippet-end:[python.cross_service.resilient_service.ec2.DeleteLaunchTemplate]

    # snippet-start:[python.cross_service.resilient_service.ec2.DescribeAvailabilityZones]
    def get_availability_zones(self) -> list:
        """
        Gets a list of Availability Zones in the AWS Region of the Amazon EC2 client.

        :return: The list of Availability Zones for the client Region.
        :raises Exception: If the availability zones could not be retrieved.
        """
        try:
            response = self.ec2_client.describe_availability_zones()
            zones = [zone["ZoneName"] for zone in response["AvailabilityZones"]]
        except ClientError as err:
            raise Exception(f"Couldn't get availability zones: {err}.")
        else:
            return zones

    # snippet-end:[python.cross_service.resilient_service.ec2.DescribeAvailabilityZones]

    # snippet-start:[python.cross_service.resilient_service.auto-scaling.CreateAutoScalingGroup]
    def create_group(self, group_size: int) -> list:
        """
        Creates an EC2 Auto Scaling group with the specified size.

        :param group_size: The number of instances to set for the minimum and maximum in the group.
        :return: The list of Availability Zones specified for the group.
        :raises Exception: If the Auto Scaling group could not be created.
        """
        zones = []
        try:
            breakpoint()
            zones = self.get_availability_zones()
            time.sleep(10)
            self.autoscaling_client.create_auto_scaling_group(
                AutoScalingGroupName=self.group_name,
                AvailabilityZones=zones,
                LaunchTemplate={
                    "LaunchTemplateName": self.launch_template_name,
                    "Version": "$Default",
                },
                MinSize=group_size,
                MaxSize=group_size,
            )
            log.info(
                "Created EC2 Auto Scaling group %s with availability zones %s.",
                self.launch_template_name,
                zones,
            )
        except ClientError as err:
            error_code = err.response["Error"]["Code"]
            if error_code == "AlreadyExists":
                log.error(
                    "EC2 Auto Scaling group %s already exists, nothing to do.",
                    self.group_name,
                )
            elif error_code == "ValidationError":
                log.error(
                    f"Failed to create auto scaling group '{self.group_name}'! "
                    "Check the parameters used and ensure that they conform to the expected format and constraints."
                )
            raise
        return zones

    # snippet-end:[python.cross_service.resilient_service.auto-scaling.CreateAutoScalingGroup]

    # snippet-start:[python.cross_service.resilient_service.auto-scaling.DescribeAutoScalingGroups]
    def get_instances(self) -> list:
        """
        Gets data about the instances in the EC2 Auto Scaling group.

        :return: Data about the instances.
        :raises Exception: If the instance data could not be retrieved.
        """
        try:
            paginator = self.autoscaling_client.get_paginator(
                "describe_auto_scaling_groups"
            )
            instance_ids = []
            for page in paginator.paginate(AutoScalingGroupNames=[self.group_name]):
                if page["AutoScalingGroups"]:
                    instance_ids.extend(
                        [i["InstanceId"] for i in [0]["Instances"]]
                    )
            return instance_ids
        except ClientError as err:
            # Add custom handling here.
            raise Exception(f"AWS EC2 Client returned an error when getting instances: \n\t{err}")

    # snippet-end:[python.cross_service.resilient_service.auto-scaling.DescribeAutoScalingGroups]

    def terminate_instance(self, instance_id: str):
        """
        Terminates an instance in an EC2 Auto Scaling group. After an instance is
        terminated, it can no longer be accessed.

        :param instance_id: The ID of the instance to terminate.
        :raises Exception: If the instance could not be terminated.
        """
        try:
            self.autoscaling_client.terminate_instance_in_auto_scaling_group(
                InstanceId=instance_id, ShouldDecrementDesiredCapacity=False
            )
            log.info(f"Terminated instance {instance_id}.")
        except ClientError as err:
            # Add custom handling here.
            raise Exception(f"Couldn't terminate instance {instance_id}: {err}")

    # snippet-start:[python.cross_service.resilient_service.auto-scaling.AttachLoadBalancerTargetGroups]
    def attach_load_balancer_target_group(self, lb_target_group: dict):
        """
        Attaches an Elastic Load Balancing (ELB) target group to this EC2 Auto Scaling group.
        The target group specifies how the load balancer forwards requests to the instances in the group.

        :param lb_target_group: Data about the ELB target group to attach.
        :raises Exception: If the target group could not be attached.
        """
        try:
            self.autoscaling_client.attach_load_balancer_target_groups(
                AutoScalingGroupName=self.group_name,
                TargetGroupARNs=[lb_target_group["TargetGroupArn"]],
            )
            log.info(
                "Attached load balancer target group %s to auto scaling group %s.",
                lb_target_group["TargetGroupName"],
                self.group_name,
            )
        except ClientError as err:
            error_code = err.response["Error"]["Code"]
            if error_code == "ValidationError":
                log.error(
                    "Couldn't attach the load balancer target group due to a validation error. "
                    "Check the parameters used and ensure that they conform to the expected format and constraints."
                )
            elif error_code == "ResourceInUse":
                log.error(
                    "Couldn't attach the load balancer target group because the resource is currently in use. "
                    "Try again later or ensure the resource is not being modified or deleted."
                )
            raise

    # snippet-end:[python.cross_service.resilient_service.auto-scaling.AttachLoadBalancerTargetGroups]

    # snippet-start:[python.cross_service.resilient_service.auto-scaling.DeleteAutoScalingGroup]
    def _try_terminate_instance(self, inst_id: str):
        """
        Tries to terminate an instance in the Auto Scaling group.

        :param inst_id: The ID of the instance to terminate.
        :raises Exception: If the instance could not be terminated.
        """
        stopping = False
        log.info(f"Stopping {inst_id}.")
        while not stopping:
            try:
                self.autoscaling_client.terminate_instance_in_auto_scaling_group(
                    InstanceId=inst_id, ShouldDecrementDesiredCapacity=True
                )
                stopping = True
            except ClientError as err:
                error_code = err.response["Error"]["Code"]
                if error_code == "ScalingActivityInProgress":
                    log.info("Scaling activity in progress for %s. Waiting...", inst_id)
                    time.sleep(10)
                elif error_code == "InvalidInstanceID.NotFound":
                    log.error(
                        f"Couldn't terminate instance because the instance ID {inst_id} was not found. "
                        "Please ensure that the instance ID is correct and try again."
                    )
                raise

    def _try_delete_group(self):
        """
        Tries to delete the EC2 Auto Scaling group. If the group is in use or in progress,
        the function waits and retries until the group is successfully deleted.

        :raises Exception: If the group could not be deleted.
        """
        stopped = False
        while not stopped:
            try:
                self.autoscaling_client.delete_auto_scaling_group(
                    AutoScalingGroupName=self.group_name
                )
                stopped = True
                log.info("Deleted EC2 Auto Scaling group %s.", self.group_name)
            except ClientError as err:
                error_code = err.response["Error"]["Code"]
                if (
                    error_code == "ResourceInUse"
                    or error_code == "ScalingActivityInProgress"
                ):
                    log.info(
                        "Some instances are still running. Waiting for them to stop..."
                    )
                    time.sleep(10)
                elif error_code == "ValidationError":
                    log.error(
                        "Couldn't delete the Auto Scaling group due to a validation error. "
                        "Check the parameters used and ensure that they conform to the expected format and constraints."
                    )
                raise

    def delete_group(self):
        """
        Terminates all instances in the group, deletes the EC2 Auto Scaling group.

        :raises Exception: If the group or its instances could not be deleted.
        """
        try:
            paginator = self.autoscaling_client.get_paginator(
                "describe_auto_scaling_groups"
            )
            groups = []
            for page in paginator.paginate(AutoScalingGroupNames=[self.group_name]):
                groups.extend(page.get("AutoScalingGroups", []))

            if len(groups) > 0:
                self.autoscaling_client.update_auto_scaling_group(
                    AutoScalingGroupName=self.group_name, MinSize=0
                )
                instance_ids = [inst["InstanceId"] for inst in groups[0]["Instances"]]
                for inst_id in instance_ids:
                    self._try_terminate_instance(inst_id)
                self._try_delete_group()
            else:
                log.info("No groups found named %s, nothing to do.", self.group_name)
        except ClientError as err:
            error_code = err.response["Error"]["Code"]
            if error_code == "ValidationError":
                log.error(
                    f"Validation error when deleting Auto Scaling group. "
                    "Check the parameters used and ensure that they conform to the expected format and constraints."
                )
            raise

    # snippet-end:[python.cross_service.resilient_service.auto-scaling.DeleteAutoScalingGroup]

    # snippet-start:[python.cross_service.resilient_service.ec2.DescribeVpcs]
    def get_default_vpc(self) -> dict:
        """
        Gets the default VPC for the account.

        :return: Data about the default VPC.
        """
        response = self.ec2_client.describe_vpcs(
            Filters=[{"Name": "is-default", "Values": ["true"]}]
        )
        return response["Vpcs"][0]

    # snippet-end:[python.cross_service.resilient_service.ec2.DescribeVpcs]

    # snippet-start:[python.cross_service.resilient_service.ec2.DescribeSecurityGroups]
    def verify_inbound_port(self, vpc: dict, port: int, ip_address: str) -> tuple:
        """
        Verify the default security group of the specified VPC allows ingress from this
        computer.

        :param vpc: The VPC used by this example.
        :param port: The port to verify.
        :param ip_address: This computer's IP address.
        :return: The default security group of the specified VPC, and a value indicating whether the port is open.
        :raises Exception: If the security group information could not be verified.
        """
        try:
            response = self.ec2_client.describe_security_groups(
                Filters=[
                    {"Name": "group-name", "Values": ["default"]},
                    {"Name": "vpc-id", "Values": [vpc["VpcId"]]},
                ]
            )
            sec_group = response["SecurityGroups"][0]
            port_is_open = False
            log.info("Found default security group %s.", sec_group["GroupId"])
            for ip_perm in sec_group["IpPermissions"]:
                if ip_perm.get("FromPort", 0) == port:
                    log.info("Found inbound rule: %s", ip_perm)
                    for ip_range in ip_perm["IpRanges"]:
                        cidr = ip_range.get("CidrIp", "")
                        if cidr.startswith(ip_address) or cidr == "0.0.0.0/0":
                            port_is_open = True
                    if ip_perm["PrefixListIds"]:
                        port_is_open = True
                    if not port_is_open:
                        log.info(
                            "The inbound rule does not appear to be open to either this computer's IP\n"
                            "address of %s, to all IP addresses (0.0.0.0/0), or to a prefix list ID.",
                            ip_address,
                        )
                    else:
                        break
        except ClientError as err:
            raise Exception(
                f"Couldn't verify inbound rule for port {port} for VPC {vpc['VpcId']}: {err}"
            )
        else:
            return sec_group, port_is_open

    # snippet-end:[python.cross_service.resilient_service.ec2.DescribeSecurityGroups]

    # snippet-start:[python.cross_service.resilient_service.ec2.AuthorizeSecurityGroupIngress]
    def open_inbound_port(self, sec_group_id: str, port: int, ip_address: str):
        """
        Add an ingress rule to the specified security group that allows access on the
        specified port from the specified IP address.

        :param sec_group_id: The ID of the security group to modify.
        :param port: The port to open.
        :param ip_address: The IP address that is granted access.
        :raises Exception: If the ingress rule could not be added.
        """
        try:
            self.ec2_client.authorize_security_group_ingress(
                GroupId=sec_group_id,
                CidrIp=f"{ip_address}/32",
                FromPort=port,
                ToPort=port,
                IpProtocol="tcp",
            )
            log.info(
                "Authorized ingress to %s on port %s from %s.",
                sec_group_id,
                port,
                ip_address,
            )
        except ClientError as err:
            raise Exception(
                f"Couldn't authorize ingress to {sec_group_id} on port {port} from {ip_address}: {err}"
            )

    # snippet-end:[python.cross_service.resilient_service.ec2.AuthorizeSecurityGroupIngress]

    # snippet-start:[python.cross_service.resilient_service.ec2.DescribeSubnets]
    def get_subnets(self, vpc_id: str, zones: list) -> list:
        """
        Gets the default subnets in a VPC for a specified list of Availability Zones.

        :param vpc_id: The ID of the VPC to look up.
        :param zones: The list of Availability Zones to look up.
        :return: The list of subnets found.
        :raises Exception: If the subnets could not be retrieved.
        """
        try:
            response = self.ec2_client.describe_subnets(
                Filters=[
                    {"Name": "vpc-id", "Values": [vpc_id]},
                    {"Name": "availability-zone", "Values": zones},
                    {"Name": "default-for-az", "Values": ["true"]},
                ]
            )
            subnets = response["Subnets"]
            log.info("Found %s subnets for the specified zones.", len(subnets))
        except ClientError:
            if error_code == "InvalidParameterValue":
                log.error(
                    f"Check that the VPC ID '{vpc_id}' exists and is correctly formatted. "
                    f"Ensure provided availability zones are valid in this region."
                    "For specifications, see: "
                    f"\n\thttps://docs.aws.amazon.com/AWSEC2/latest/UserGuide/using-regions-availability-zones.html."
                )
            raise
        else:
            return subnets

    # snippet-end:[python.cross_service.resilient_service.ec2.DescribeSubnets]


# snippet-end:[python.example_code.workflow.ResilientService_AutoScaler]
