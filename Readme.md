# Sonacloud - Computing Infrastructure as a Service

## Overview

This Flask web application provides a user and admin portal for managing virtual machines in an educational institution using the CloudStack Management API. Users can easily request and create VMs without the need for understanding the complexity of the underlying infrastructure.

## Features

- **User Portal:**
  - Allows users to request and create VMs.
  - Provides a user-friendly interface for managing VM-related tasks.

- **Admin Portal:**
  - Enables administrators to oversee and manage VM requests.
  - Provides tools for monitoring and controlling the virtualized infrastructure.

## Usage

1. **User Registration:**
   - Users need to register for an account.

2. **User Authentication:**
   - Upon registration, users can log in to the system.

3. **VM Request:**
   - Users can request the creation of VMs through an intuitive interface.

4. **Admin Approval:**
   - Admins review and approve VM requests.

5. **VM Management:**
   - Users and admins can monitor, start, stop, and delete VMs.

## Configuration

1. **CloudStack API Keys:**
   - Set the CloudStack API keys in the environment variables.
     ```env
     CLOUDSTACK_API_KEY=your-api-key
     CLOUDSTACK_SECRET_KEY=your-secret-key
     ```

2. **Environment Configuration:**
   - Customize other configuration settings in the `.env` file.

## Contributing

We welcome contributions! If you'd like to contribute to this project, please follow our [Contribution Guidelines](CONTRIBUTING.md).

## License

This project is licensed under the [MIT License](LICENSE).
