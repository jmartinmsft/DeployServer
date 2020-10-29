# DeployServer
Deploy domain controllers and Exchange servers using PowerShell.

There are a few steps you need to take before you can begin deploying servers. The first step is to create a base image of Windows that can be used by the deployment script. It is recommended that you install the latest Windows updates. You can also install all of the Exchange prerequisites, but not required. Copy all the files into the C:\Temp directory on your VM host.

Once you have your Windows server VM ready, you copy the following two scripts and the unattend.xml file onto the server in the C:\Temp directory. These scripts do the following:
1.	Sysprep-VirtualMachine – This script gets the administrator credentials for the Hyper-V host and stores credentials into a psd1 file on the machine. It then runs sysprep on the VM using the unattend.xml.
2.	Start-Setup – This script begins the VM setup process by copying the necessary files from the Hyper-V host.

The next step is to run the Sysprep-Virtual machine script to prepare your VM. It is recommended to mark this VHD are read only to prevent accidental use in another VM. The deployment process copies this VHD as its source and removes the read-only flag if needed.

At this point you are ready to deploy one or more Exchange servers using the Deploy-Servers script. This script prompts you for some basic information needed to deploy the servers. Once it has that information, it create a new VM and starts the VM and the sysprep’d image completes the setup process.

You can only use this deployment script to repave your existing Exchange servers. For example, you can update your base VHD image with the latest Windows update. Then instead of installing those updates across all your VMs, you can run this process to restore the Exchange servers. You can also update to the latest CU. 

Here are some of the features:
1.  Deploy one or more AD Domain Controllers or Exchange servers
2.	Deploy a new Active Directory forest
3.  Deploy a new Exchange organization
4.	Create one or more AD sites deploy a DAG across multiple sites…)
5.	Create a DAG with one or more IP addresses or IP-less only


