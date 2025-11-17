Frontend Url=> job-portal-five-henna.vercel.app
Backend Url=> https://jobportal-fkdm.onrender.com


Project Title: CareerLink – Job Portal Site


Problem Statement:
Finding and applying for jobs is often fragmented across multiple platforms, making it difficult for job
seekers and recruiters to connect efficiently. CareerLink aims to simplify this process by providing a
unified platform where employers can post job openings, and job seekers can browse, apply, and
track their applications easily.
System Architecture:
Frontend → Backend (API) → Database
Frontend: React.js with React Router for page navigation
Backend: Node.js + Express
Database: MongoDB (non-relational) / PostgreSQL (relational)
Authentication: JWT-based login/signup
Hosting:
Frontend → Netlify/Vercel
Backend → Render/Railway
Database → MongoDB Atlas / ElephantSQL / Aiven
Key Features:

Category | Features
Authentication & Authorization — User registration, login, logout, role-based access (admin/user)
CRUD Operations — Create, read, update, delete job listings and user data
Frontend Routing — Pages: Home, Login, Dashboard, Job Details, Profile, Post Job
Job Management — Recruiters can post, edit, and delete jobs
Application System — Job seekers can apply for jobs and track their status
Data Operations — Searching, sorting, filtering, and pagination of job listings for efficient data handling
Hosting — Deployed on Vercel (frontend) and Render (backend) with MongoDB Atlas



Tech Stack:
Frontend: React.js, React Router, Axios, TailwindCSS/Bootstrap
Backend: Node.js, Express.js
Database: MongoDB / PostgreSQL
Authentication: JWT / OAuth
Hosting: Vercel, Render, Netlify, Railway
API Overview:
/api/auth/signup – Register new user (Public)
/api/auth/login – Authenticate user (Public)
/api/jobs – Get all job listings (Authenticated)
/api/jobs/:id – Update job listing (Authenticated)
/api/jobs/:id – Delete job listing (Admin only)
# FlexVault
